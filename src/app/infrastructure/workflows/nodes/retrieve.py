"""`retrieve_and_prepare_data` worker-graph node.

Fetches the scan, builds the repository map + dependency graph, and
resolves the relevant agents from the selected frameworks.

The string name registered via `workflow.add_node("retrieve_and_prepare_data", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import RelevantAgent, WorkerState
from app.shared.analysis_tools.context_bundler import ContextBundlingEngine
from app.shared.analysis_tools.repository_map import RepositoryMappingEngine
from app.shared.lib.scan_progress import EV_COMPLETED, EV_STARTED

logger = logging.getLogger(__name__)

# Business-logic caps (V02.2.1, V02.3.2)
MAX_FILES_PER_SCAN = 10_000
MAX_FRAMEWORKS = 32
MAX_AGENTS = 200

_NEWLINE_RE = re.compile(r"[\r\n]")


def _sanitize(value: str) -> str:
    """Replace CR/LF with literal escapes to prevent log-injection (V16.4.1)."""
    return _NEWLINE_RE.sub(lambda m: "\\r" if m.group() == "\r" else "\\n", value)


async def retrieve_and_prepare_data_node(state: WorkerState) -> Dict[str, Any]:
    """
    Node to retrieve all initial data, create the repo map, and dependency graph.
    """
    scan_id = state["scan_id"]
    logger.info("Entering retrieve_and_prepare_data scan_id=%s", scan_id)
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)

            # --- FETCH SCAN FIRST to get its status ---
            scan = await repo.get_scan_with_details(scan_id)
            if not scan:
                return {"error_message": f"Scan with ID {scan_id} not found."}

            # Capture the status before updating the DB
            current_status = scan.status

            # Stage STARTED — records the event and advances the
            # scans.status cache to ANALYZING_CONTEXT (#84).
            await repo.record_scan_event(scan_id, "ANALYZING_CONTEXT", EV_STARTED)

            original_snapshot = next(
                (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
                None,
            )
            if not original_snapshot:
                return {
                    "error_message": f"Original code snapshot not found for scan {scan_id}."
                }

            # V02.2.1 / V02.3.2: enforce per-scan file count cap
            if len(original_snapshot.file_map) > MAX_FILES_PER_SCAN:
                return {
                    "error_message": (
                        f"Scan {scan_id} exceeds MAX_FILES_PER_SCAN ({MAX_FILES_PER_SCAN})."
                    )
                }

            files_map = await repo.get_source_files_by_hashes(
                list(original_snapshot.file_map.values())
            )

            # V02.2.3: enforce snapshot ↔ source-file consistency
            missing = [
                path
                for path, h in original_snapshot.file_map.items()
                if h not in files_map
            ]
            if missing:
                return {
                    "error_message": (
                        f"Scan {scan_id} snapshot references missing source files: "
                        f"{missing[:5]}"
                    )
                }

            files = {
                path: files_map[h] for path, h in original_snapshot.file_map.items()
            }

            # Create Repo Map
            mapping_engine = RepositoryMappingEngine()
            repository_map = mapping_engine.create_map(files)
            logger.debug(
                "repository_map_built scan_id=%s file_count=%d",
                scan_id,
                len(repository_map.files),
            )

            # Create Dependency Graph
            bundling_engine = ContextBundlingEngine(repository_map, files)
            dependency_graph = bundling_engine.graph
            logger.debug(
                "dependency_graph_built scan_id=%s nodes=%d edges=%d",
                scan_id,
                dependency_graph.number_of_nodes(),
                dependency_graph.number_of_edges(),
            )

            # Determine Relevant Agents
            # V02.2.1 / V02.3.2: cap framework list, reject garbage entries
            frameworks = [
                f
                for f in (scan.frameworks or [])
                if isinstance(f, str) and 1 <= len(f) <= 64
            ][:MAX_FRAMEWORKS]

            framework_details = await db.execute(
                select(db_models.Framework)
                .options(selectinload(db_models.Framework.agents))
                .where(db_models.Framework.name.in_(frameworks))
            )
            # Store full agent details for the triage step
            all_relevant_agents = {
                agent.name: RelevantAgent(
                    name=agent.name,
                    description=agent.description,
                    domain_query=agent.domain_query,
                )
                for framework in framework_details.scalars().all()
                for agent in framework.agents
            }

            # V02.3.2: cap resolved agent count
            if len(all_relevant_agents) > MAX_AGENTS:
                all_relevant_agents = dict(
                    list(all_relevant_agents.items())[:MAX_AGENTS]
                )

            # --- FIX: Add this block to explicitly save the artifacts ---
            serialized_graph = nx.node_link_data(dependency_graph)
            await repo.update_scan_artifacts(
                scan_id,
                {
                    "repository_map": repository_map.model_dump(),
                    "dependency_graph": serialized_graph,
                },
            )
            # --- End of FIX ---

            # Stage COMPLETED — closes out the ANALYZING_CONTEXT stage
            # on the event-sourced timeline (#84).
            await repo.record_scan_event(scan_id, "ANALYZING_CONTEXT", EV_COMPLETED)

            return {
                "scan_type": scan.scan_type,
                "current_scan_status": current_status,
                "reasoning_llm_config_id": scan.reasoning_llm_config_id,
                "utility_llm_config_id": scan.utility_llm_config_id,
                "stage_temperatures": scan.stage_temperatures,
                "disable_temperature": scan.disable_temperature,
                "cross_file_validation": scan.cross_file_validation,
                "files": files,
                "initial_file_map": original_snapshot.file_map,
                "live_codebase": files.copy(),
                "repository_map": repository_map,
                "dependency_graph": nx.node_link_data(dependency_graph),
                "findings": [],
                "all_relevant_agents": all_relevant_agents,
            }
    except Exception as e:
        logger.error(
            "retrieve_and_prepare_data error scan_id=%s err=%s",
            scan_id,
            _sanitize(str(e)),
            exc_info=True,
        )
        return {"error_message": str(e)}
