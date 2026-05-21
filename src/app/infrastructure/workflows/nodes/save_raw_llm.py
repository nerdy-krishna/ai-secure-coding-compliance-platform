"""`save_raw_llm_findings` worker-graph node.

Runs after analysis completes and before consolidation begins.
Snapshots the LLM-emitted findings (those whose ``source`` is not a
deterministic scanner) to the ``raw_llm`` bucket in the ``findings``
table.  This bucket is never deleted on restart/resume — it
accumulates every generation for agent-quality debugging.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.AsyncSessionLocal import (
    AsyncSessionLocal,
)

logger = logging.getLogger(__name__)

# Sources that are deterministic scanners (not LLM agents).
_SAST_SOURCES = frozenset({"bandit", "semgrep", "gitleaks", "osv"})


async def save_raw_llm_findings_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Persist pre-consolidation LLM findings to the raw_llm bucket.

    Reads ``state["findings"]``, filters to only LLM-emitted findings
    (excludes SAST sources), and inserts them with
    ``finding_bucket='raw_llm'``.  The SAST findings are already in the
    ``sast`` bucket (saved by the prescan node).

    This node is stateless — it does not modify ``state["findings"]``.
    """
    scan_id = state["scan_id"]
    findings: list[VulnerabilityFinding] = state.get("findings") or []
    llm_findings = [
        f for f in findings if (f.source or "").lower() not in _SAST_SOURCES
    ]
    if not llm_findings:
        logger.info("save_raw_llm: no LLM findings to snapshot for scan %s", scan_id)
        return {}

    batch = state.get("_batch", 1)
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)
            # Use save_findings which handles idempotency (skips if id
            # already set) — safe for LangGraph re-entry on resume.
            await repo.save_findings(
                scan_id, llm_findings, finding_bucket="raw_llm", batch=batch
            )
        logger.info(
            "save_raw_llm: persisted %d LLM findings for scan %s (batch %s)",
            len(llm_findings),
            scan_id,
            batch,
        )
    except Exception:
        logger.error("save_raw_llm: failed for scan %s", scan_id, exc_info=True)
        # Don't block the pipeline — consolidation still runs.

    return {}
