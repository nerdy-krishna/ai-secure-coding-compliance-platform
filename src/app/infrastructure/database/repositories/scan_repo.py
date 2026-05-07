import logging
import uuid
import datetime
import hashlib
from typing import List, Dict, Optional, Any

import sqlalchemy as sa
from sqlalchemy import String, cast, func, select, update, or_, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.infrastructure.database import models as db_models
from app.core import schemas as agent_schemas
from app.shared.lib.scan_status import STATUS_QUEUED

logger = logging.getLogger(__name__)

_MAX_PAGE_LIMIT = 100


class ScanRepository:
    """
    Handles all database operations related to projects, scans, code snapshots,
    findings, and their associated data.

    Cross-tenant invariant (H.2): Every public method that takes a
    scan_id/project_id MUST take requesting_user_id and visible_user_ids
    and forward both to _scope_column at the SQL layer; do not rely on
    upstream auth alone — H.2 cross-tenant invariant.  List/search paths
    already enforce this.  Single-resource read/write methods are being
    migrated incrementally; track progress via V08.2.2 remediation issues.
    """

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def get_or_create_project(
        self,
        name: str,
        user_id: int,
        repo_url: Optional[str] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> db_models.Project:
        """Retrieves a project by name for a user, or creates it if it doesn't exist.

        Uses an atomic INSERT ... ON CONFLICT DO NOTHING to avoid the TOCTOU
        race where two concurrent callers both miss the existence check and
        both attempt INSERT, causing an IntegrityError (V15.4.2).

        ``tenant_id`` (Chunk 9) is the caller's tenant. Stamped on
        creation so per-tenant enforcement filters are correct from
        the first row. Existing rows keep whatever the backfill set;
        the ON CONFLICT path doesn't overwrite.
        """
        values: Dict[str, Any] = {
            "name": name,
            "user_id": user_id,
            "repository_url": repo_url,
        }
        if tenant_id is not None:
            values["tenant_id"] = tenant_id
        insert_stmt = (
            pg_insert(db_models.Project)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["name", "user_id"])
        )
        try:
            await self.db.execute(insert_stmt)
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.get_or_create_project.commit_failed",
                extra={
                    "project_name": name,
                    "user_id": user_id,
                    "error_class": e.__class__.__name__,
                },
                exc_info=True,
            )
            raise

        stmt = select(db_models.Project).filter_by(name=name, user_id=user_id)
        result = await self.db.execute(stmt)
        project = result.scalars().first()
        if project is None:
            raise RuntimeError(
                f"get_or_create_project: could not find project after upsert for name={name!r} user_id={user_id}"
            )
        logger.info(
            "scan_repo.project.created",
            extra={"project_name": name, "user_id": user_id},
        )
        return project

    async def create_scan(
        self,
        project_id: uuid.UUID,
        user_id: int,
        scan_type: str,
        reasoning_llm_config_id: uuid.UUID,
        frameworks: List[str],
        tenant_id: Optional[uuid.UUID] = None,
    ) -> db_models.Scan:
        """Creates a new Scan record. ``tenant_id`` is stamped from the
        submitter so the per-tenant scope filter (Chunk 9) is correct
        for newly-created scans."""
        logger.info(
            "scan_repo.scan.created",
            extra={"project_id": str(project_id), "scan_type": scan_type},
        )
        scan = db_models.Scan(
            project_id=project_id,
            user_id=user_id,
            scan_type=scan_type,
            status=STATUS_QUEUED,
            reasoning_llm_config_id=reasoning_llm_config_id,
            frameworks=frameworks,
            tenant_id=tenant_id,
        )
        self.db.add(scan)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.create_scan.commit_failed",
                extra={
                    "project_id": str(project_id),
                    "error_class": e.__class__.__name__,
                },
                exc_info=True,
            )
            raise
        await self.db.refresh(scan)
        return scan

    async def get_or_create_source_files(
        self, files_data: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Accepts a list of files, hashes them, and saves new ones to the database.
        Returns a list of all file hashes for the given input.

        Uses INSERT ... ON CONFLICT (hash) DO NOTHING for atomic deduplication
        to eliminate the TOCTOU race when two concurrent scans submit identical
        content (V15.4.2).
        """
        file_hashes = []
        rows_to_upsert = []
        seen_hashes: set = set()
        for file_data in files_data:
            content = file_data["content"]
            hasher = hashlib.sha256()
            hasher.update(content.encode("utf-8"))
            file_hash = hasher.hexdigest()
            file_hashes.append(file_hash)

            if file_hash not in seen_hashes:
                seen_hashes.add(file_hash)
                rows_to_upsert.append(
                    {
                        "hash": file_hash,
                        "content": content,
                        "language": file_data.get("language", "unknown"),
                    }
                )

        if rows_to_upsert:
            logger.info(
                "scan_repo.source_files.upserted",
                extra={"unique_file_count": len(rows_to_upsert)},
            )
            stmt = (
                pg_insert(db_models.SourceCodeFile)
                .values(rows_to_upsert)
                .on_conflict_do_nothing(index_elements=["hash"])
            )
            try:
                await self.db.execute(stmt)
                await self.db.commit()
            except SQLAlchemyError as e:
                logger.error(
                    "scan_repo.get_or_create_source_files.commit_failed",
                    extra={"error_class": e.__class__.__name__},
                    exc_info=True,
                )
                raise

        return file_hashes

    async def create_code_snapshot(
        self, scan_id: uuid.UUID, file_map: Dict[str, str], snapshot_type: str
    ) -> db_models.CodeSnapshot:
        """Creates a code snapshot record for a scan."""
        snapshot = db_models.CodeSnapshot(
            scan_id=scan_id, file_map=file_map, snapshot_type=snapshot_type
        )
        self.db.add(snapshot)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.create_code_snapshot.commit_failed",
                extra={"scan_id": str(scan_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise
        await self.db.refresh(snapshot)
        return snapshot

    async def get_scan(self, scan_id: uuid.UUID) -> Optional[db_models.Scan]:
        """Retrieves a single scan by its ID.

        NOTE: Returns the full ORM row including internal JSONB blobs
        (cost_details, repository_map, dependency_graph, context_bundles,
        bom_cyclonedx).  Service callers building user-facing responses
        should use get_scan_summary() instead to avoid accidental
        serialisation of internal data (V15.3.1).

        Eager-loads `events` because the SSE stream re-reads the scan on
        every NOTIFY (`stream_scan_progress`) and reads `scan.events` to
        diff new stage rows. Without this, async lazy-loading of the
        relationship is unreliable and the live event log silently
        stops ticking forward mid-scan.
        """
        logger.debug("Fetching scan from DB.", extra={"scan_id": str(scan_id)})
        result = await self.db.execute(
            select(db_models.Scan)
            .options(selectinload(db_models.Scan.events))
            .filter(db_models.Scan.id == scan_id)
        )
        return result.scalars().first()

    async def get_scan_summary(self, scan_id: uuid.UUID) -> Optional[Any]:
        """Retrieves a lightweight projection of a scan for user-facing responses.

        Returns only public fields; heavy JSONB blobs (repository_map,
        dependency_graph, context_bundles, cost_details, bom_cyclonedx)
        are excluded (V15.3.1).
        """
        logger.debug("Fetching scan summary from DB.", extra={"scan_id": str(scan_id)})
        result = await self.db.execute(
            select(
                db_models.Scan.id,
                db_models.Scan.status,
                db_models.Scan.scan_type,
                db_models.Scan.project_id,
                db_models.Scan.user_id,
                db_models.Scan.risk_score,
                db_models.Scan.created_at,
                db_models.Scan.completed_at,
            ).filter(db_models.Scan.id == scan_id)
        )
        return result.first()

    async def get_scan_with_details(
        self, scan_id: uuid.UUID
    ) -> Optional[db_models.Scan]:
        """Retrieves a scan with its related snapshots, findings, and project.

        WARNING: The full ORM row includes heavy JSONB blobs
        (repository_map, dependency_graph, context_bundles, cost_details,
        bom_cyclonedx).  These MUST be stripped before any HTTP response
        is returned to the caller (V15.3.1).
        """
        logger.debug(
            "Fetching scan with details from DB.", extra={"scan_id": str(scan_id)}
        )
        result = await self.db.execute(
            select(db_models.Scan)
            .options(
                selectinload(db_models.Scan.project),
                selectinload(db_models.Scan.snapshots),
                selectinload(db_models.Scan.findings),
                # `events` was historically lazy because the legacy
                # AnalysisResultDetailResponse didn't surface them.
                # Now the response carries the stage-event audit
                # trail so ScanRunningPage can seed the live-event-
                # log on terminal scans (where SSE has already closed
                # by the time the listener attaches). Eager-load to
                # avoid a `MissingGreenlet` when the response model
                # iterates the relationship after the async session
                # has closed.
                selectinload(db_models.Scan.events),
            )
            .filter(db_models.Scan.id == scan_id)
        )
        return result.scalars().first()

    async def update_scan_artifacts(
        self, scan_id: uuid.UUID, artifacts: Dict[str, Any]
    ):
        """Updates a scan record with large artifact JSONB data."""
        logger.info(
            "scan_repo.scan.artifacts_updated",
            extra={"scan_id": str(scan_id), "artifact_keys": list(artifacts.keys())},
        )
        stmt = (
            update(db_models.Scan)
            .where(db_models.Scan.id == scan_id)
            .values(**artifacts)
        )
        await self.db.execute(stmt)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.update_scan_artifacts.commit_failed",
                extra={"scan_id": str(scan_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

    async def update_status(self, scan_id: uuid.UUID, status: str):
        """Updates the status of a single scan."""
        # Local import — avoid pulling the messaging package + psycopg
        # at module import time, which historically caused circulars
        # during Alembic env.py setup.
        from app.infrastructure.messaging.scan_progress_notifier import (
            KIND_STATUS,
            notify_scan_progress,
        )

        logger.info(
            "Updating scan status in DB.",
            extra={"scan_id": str(scan_id), "new_status": status},
        )
        stmt = (
            update(db_models.Scan)
            .where(db_models.Scan.id == scan_id)
            .values(status=status)
        )
        await self.db.execute(stmt)
        # Emit the NOTIFY in the same transaction so it fires iff the
        # status update commits (§3.10a).
        await notify_scan_progress(self.db, scan_id=str(scan_id), kind=KIND_STATUS)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.update_status.commit_failed",
                extra={"scan_id": str(scan_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

    async def update_bom_cyclonedx(self, scan_id: uuid.UUID, bom: dict) -> None:
        """Persist the CycloneDX SBOM produced by OSV-Scanner during the
        deterministic pre-pass. ADR-009 / §3.6."""
        stmt = (
            update(db_models.Scan)
            .where(db_models.Scan.id == scan_id)
            .values(bom_cyclonedx=bom)
        )
        await self.db.execute(stmt)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.update_bom_cyclonedx.commit_failed",
                extra={"scan_id": str(scan_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

    async def create_scan_event(
        self,
        scan_id: uuid.UUID,
        stage_name: str,
        status: str = "STARTED",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Adds a new event to the scan's timeline.

        `details` (§3.10b) carries per-event context — e.g.
        `FILE_ANALYZED` events ride with `{file_path, findings_count}`
        so the SSE stream can render per-file progress mid-scan.
        Null for legacy stage events that have no extra context.
        """
        from app.infrastructure.messaging.scan_progress_notifier import (
            KIND_EVENT,
            notify_scan_progress,
        )

        logger.debug(
            "scan_repo.scan_event.added",
            extra={"scan_id": str(scan_id), "stage_name": stage_name, "status": status},
        )
        event = db_models.ScanEvent(
            scan_id=scan_id, stage_name=stage_name, status=status, details=details
        )
        self.db.add(event)
        # Notify within the same transaction (§3.10a).
        await notify_scan_progress(self.db, scan_id=str(scan_id), kind=KIND_EVENT)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.create_scan_event.commit_failed",
                extra={"scan_id": str(scan_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

    async def save_llm_interaction(
        self, interaction_data: agent_schemas.LLMInteraction
    ):
        """Saves a single LLM interaction record to the database."""
        logger.debug(
            "Saving LLM interaction to DB.",
            extra={
                "scan_id": str(interaction_data.scan_id),
                "agent_name": interaction_data.agent_name,
            },
        )
        # V14.2.7 — stamp retention expiry from the cached config.
        from app.core.config_cache import (
            RETENTION_KIND_LLM_INTERACTION,
            SystemConfigCache,
        )

        retention_days = SystemConfigCache.get_retention_days(
            RETENTION_KIND_LLM_INTERACTION
        )
        payload = interaction_data.model_dump()
        if retention_days > 0:
            payload["expires_at"] = datetime.datetime.now(
                datetime.timezone.utc
            ) + datetime.timedelta(days=retention_days)
        db_interaction = db_models.LLMInteraction(**payload)
        self.db.add(db_interaction)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.save_llm_interaction.commit_failed",
                extra={
                    "scan_id": str(interaction_data.scan_id),
                    "error_class": e.__class__.__name__,
                },
                exc_info=True,
            )
            raise

    async def save_findings(
        self, scan_id: uuid.UUID, findings: List[agent_schemas.VulnerabilityFinding]
    ):
        """Inserts vulnerability findings for a scan and hydrates the
        DB-assigned ``id`` back onto each input Pydantic schema.

        Hydrating ``id`` matters for the deterministic-prescan pipeline:
        the LangGraph state carries the same finding objects through to
        ``save_results_node``, which uses the presence of an ``id`` to
        decide whether the row is fresh (insert) or already persisted
        (update only). Without this hydration, the results node re-
        inserts every prescan finding a second time.

        Findings whose ``id`` is already populated are skipped — they
        were inserted by an earlier call (LangGraph node re-entry on
        resume) and re-inserting would dupe the row. This makes
        ``save_findings`` idempotent against the input list.
        """
        if not findings:
            return

        # Skip already-persisted findings (id already set) — defends
        # against double-insert when a node calling this is re-entered
        # by LangGraph after an interrupt() resume.
        new_findings = [f for f in findings if f.id is None]
        if not new_findings:
            return

        # Resolve the parent scan's tenant once (Chunk 9). Stamped on every
        # inserted Finding so per-tenant filters on /admin/findings + the
        # dashboard work without joining back to scans.
        scan_tenant_id = (
            await self.db.execute(
                select(db_models.Scan.tenant_id).where(db_models.Scan.id == scan_id)
            )
        ).scalar_one_or_none()

        db_findings: List[db_models.Finding] = []
        for f in new_findings:
            # For new findings, ensure ID is not set
            finding_dict = f.model_dump(exclude_unset=True, exclude={"id"})

            # FIX: Preserve the generating agent's name in the corroborating_agents list
            agent_name = finding_dict.pop("agent_name", None)
            if agent_name and not finding_dict.get("corroborating_agents"):
                finding_dict["corroborating_agents"] = [agent_name]

            db_findings.append(
                db_models.Finding(
                    scan_id=scan_id, tenant_id=scan_tenant_id, **finding_dict
                )
            )

        self.db.add_all(db_findings)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.save_findings.commit_failed",
                extra={"scan_id": str(scan_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

        # Hydrate the DB-assigned ids back onto the input Pydantic
        # schemas, in order. SQLAlchemy populates `db_findings[i].id`
        # after `add_all` + commit; we pair by index since both lists
        # were built in the same iteration.
        for schema, row in zip(new_findings, db_findings):
            schema.id = row.id

    async def update_correlated_findings(
        self, findings: List[agent_schemas.VulnerabilityFinding]
    ):
        """Updates existing findings with correlation data + remediation flags.

        Carries `corroborating_agents`, `confidence`, `is_applied_in_remediation`
        (set by `consolidate_and_patch_node`), and `fix_verified` (set by
        the §3.9 patch verifier) from the in-memory finding objects back
        to the row that was originally inserted by the deterministic-
        prescan node. Findings without an `id` are skipped — they were
        produced by an LLM agent at analyze time and are inserted fresh
        elsewhere.
        """
        if not findings:
            return

        for finding in findings:
            if finding.id:  # Ensure we have an ID to perform the update
                stmt = (
                    update(db_models.Finding)
                    .where(db_models.Finding.id == finding.id)
                    .values(
                        corroborating_agents=finding.corroborating_agents,
                        confidence=finding.confidence,
                        is_applied_in_remediation=finding.is_applied_in_remediation,
                        fix_verified=finding.fix_verified,
                    )
                )
                await self.db.execute(stmt)

        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.update_correlated_findings.commit_failed",
                extra={"error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

    async def get_findings_for_scan_and_file(
        self, scan_id: uuid.UUID, file_path: str
    ) -> List[db_models.Finding]:
        """Retrieves all findings for a specific file within a scan."""
        stmt = select(db_models.Finding).where(
            db_models.Finding.scan_id == scan_id,
            db_models.Finding.file_path == file_path,
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_findings_for_scan(
        self, scan_id: uuid.UUID
    ) -> List[db_models.Finding]:
        """All findings for a scan, ordered by severity then id (ADR-009 G6).

        Used by the prescan-approval card on the scan-status page to
        render the deterministic findings before the operator clears
        the LLM gate.
        """
        stmt = (
            select(db_models.Finding)
            .where(db_models.Finding.scan_id == scan_id)
            .order_by(db_models.Finding.id.asc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def query_findings(
        self,
        *,
        visible_user_ids: Optional[List[int]],
        source_filter: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[int] = None,
    ) -> List[db_models.Finding]:
        """List findings across scans with admin-scope filtering.

        N7 (sast-prescan-followups): the visibility-scope filter is
        applied at the SQL layer (`Scan.user_id IN (visible_user_ids)`)
        when ``visible_user_ids`` is non-None; admins pass ``None`` and
        the filter is skipped. The optional ``source_filter`` constrains
        to a single scanner provenance (``"bandit"`` / ``"semgrep"`` /
        ``"gitleaks"`` / ``"agent"``).

        Cursor pagination uses ``Finding.id`` descending as the primary
        sort so pages are deterministic and disjoint. Severity is
        surfaced as a column in the admin UI for visual scanning;
        keeping the SQL sort to a single monotonic key makes
        ``id < cursor`` cursoring correct without composite-cursor
        plumbing (close-features-4-6 fix).
        """
        limit = max(1, min(int(limit), _MAX_PAGE_LIMIT))

        if visible_user_ids is not None and not visible_user_ids:
            logger.debug(
                "scan_repo.query.scope_self_only",
                extra={"method": "query_findings"},
            )

        stmt = (
            select(db_models.Finding)
            .join(db_models.Scan, db_models.Scan.id == db_models.Finding.scan_id)
            .order_by(db_models.Finding.id.desc())
            .limit(limit)
        )
        if visible_user_ids is not None:
            stmt = stmt.where(db_models.Scan.user_id.in_(visible_user_ids))
        if source_filter is not None:
            stmt = stmt.where(db_models.Finding.source == source_filter)
        if cursor is not None:
            stmt = stmt.where(db_models.Finding.id < cursor)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def count_findings_by_source(
        self,
        scan_id: uuid.UUID,
        *,
        visible_user_ids: Optional[List[int]] = None,
    ) -> Dict[str, int]:
        """Per-source finding counts for a single scan.

        Used by the per-source counter (Group D2) on the scan results
        page. NULL `source` is bucketed as ``"agent"`` (legacy
        LLM-emitted findings before the source backfill ran).

        `visible_user_ids` (defensive scope per Feature-7 F3): admins
        pass `None` (no filter); regular users pass `[user.id, ...peers]`
        and the query will only count findings whose owning scan is
        visible. Today's only caller (`ScanQueryService.get_scan_result`)
        already authorizes upstream so the filter is a no-op there;
        the kwarg hardens future callers against accidental cross-tenant
        leakage.
        """
        if visible_user_ids is not None and not visible_user_ids:
            logger.debug(
                "scan_repo.query.scope_self_only",
                extra={"method": "count_findings_by_source", "scan_id": str(scan_id)},
            )

        bucket = sa.func.coalesce(db_models.Finding.source, "agent")
        stmt = (
            select(bucket.label("source"), sa.func.count(db_models.Finding.id))
            .where(db_models.Finding.scan_id == scan_id)
            .group_by(bucket)
        )
        if visible_user_ids is not None:
            stmt = stmt.join(
                db_models.Scan, db_models.Scan.id == db_models.Finding.scan_id
            ).where(db_models.Scan.user_id.in_(visible_user_ids))
        rows = (await self.db.execute(stmt)).all()
        return {str(source): int(count) for source, count in rows}

    async def mark_findings_as_applied(self, finding_ids: List[int]):
        """Sets the is_applied_in_remediation flag to true for a list of finding IDs."""
        if not finding_ids:
            return
        stmt = (
            update(db_models.Finding)
            .where(db_models.Finding.id.in_(finding_ids))
            .values(is_applied_in_remediation=True)
        )
        await self.db.execute(stmt)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.mark_findings_as_applied.commit_failed",
                extra={"error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

    async def update_cost_and_status(
        self, scan_id: uuid.UUID, status: str, estimated_cost: Dict[str, Any]
    ):
        """Atomically updates the status and the estimated cost of a scan."""
        # Sibling of `update_status`: emit a NOTIFY in the same
        # transaction so SSE subscribers wake on the cost-approval
        # status flip instead of waiting on the heartbeat fallback.
        from app.infrastructure.messaging.scan_progress_notifier import (
            KIND_STATUS,
            notify_scan_progress,
        )

        logger.info(
            "Updating cost and status in DB.",
            extra={
                "scan_id": str(scan_id),
                "new_status": status,
                "total_estimated_cost": estimated_cost.get("total_estimated_cost"),
            },
        )
        stmt = (
            update(db_models.Scan)
            .where(db_models.Scan.id == scan_id)
            .values(status=status, cost_details=estimated_cost)
        )
        await self.db.execute(stmt)
        await notify_scan_progress(self.db, scan_id=str(scan_id), kind=KIND_STATUS)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.update_cost_and_status.commit_failed",
                extra={"scan_id": str(scan_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

    async def save_final_reports_and_status(
        self,
        scan_id: uuid.UUID,
        status: str,
        summary: Optional[Dict[str, Any]],
        risk_score: Optional[int],
    ):
        """Saves the final summary + risk score, sets the completion timestamp, and updates the status."""
        logger.info(
            "Saving final reports and status to DB.",
            extra={"scan_id": str(scan_id), "new_status": status},
        )
        completed_at_aware = datetime.datetime.now(datetime.timezone.utc)
        values = {
            "status": status,
            "completed_at": completed_at_aware,
            "risk_score": risk_score,
            "summary": summary,
        }
        stmt = (
            update(db_models.Scan).where(db_models.Scan.id == scan_id).values(**values)
        )
        await self.db.execute(stmt)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "scan_repo.save_final_reports_and_status.commit_failed",
                extra={"scan_id": str(scan_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise

    async def get_project_by_id(
        self, project_id: uuid.UUID
    ) -> Optional[db_models.Project]:
        """Retrieves a single project by its ID."""
        logger.debug("Fetching project from DB.", extra={"project_id": str(project_id)})
        result = await self.db.execute(
            select(db_models.Project).filter(db_models.Project.id == project_id)
        )
        return result.scalars().first()

    async def get_scans_count_for_project(self, project_id: uuid.UUID) -> int:
        """Counts the total number of scans for a specific project."""
        stmt = select(func.count(db_models.Scan.id)).where(
            db_models.Scan.project_id == project_id
        )
        result = await self.db.execute(stmt)
        return result.scalar_one() or 0

    async def get_paginated_scans_for_project(
        self, project_id: uuid.UUID, skip: int, limit: int
    ) -> List[db_models.Scan]:
        """Retrieves a paginated list of scans for a specific project."""
        limit = max(1, min(int(limit), _MAX_PAGE_LIMIT))
        stmt = (
            select(db_models.Scan)
            .options(
                selectinload(db_models.Scan.events),
                selectinload(db_models.Scan.project),
            )
            .where(db_models.Scan.project_id == project_id)
            .order_by(db_models.Scan.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    def _scope_column(
        column: Any,
        user_id: int,
        visible_user_ids: Optional[List[int]],
    ) -> Any:
        """Build a WHERE clause for a user_id-owned column.

        `visible_user_ids=None` means "no filter at all" — reserved for
        the admin path where `scan_scope.visible_user_ids()` returned
        None. A list means "exactly these users" (always includes the
        requester; peers come from user_group memberships). Callers
        that haven't been migrated to pass the list still work — they
        fall back to the requester's own user_id.
        """
        if visible_user_ids is None:
            # Admin — no filter. Pass a tautology so the caller can
            # still `.where()` it unconditionally.
            return sa.true()
        if not visible_user_ids:
            return column == user_id
        return column.in_(visible_user_ids)

    @staticmethod
    def _scope_tenant(
        tenant_column: Any,
        tenant_id: Optional[uuid.UUID],
    ) -> Any:
        """Build a WHERE clause for a tenant_id-scoped column (Chunk 9).

        ``tenant_id is None`` → admin / no scope; returns ``sa.true()``
        so callers can ``.where()`` it unconditionally.

        ``tenant_id is set`` → restrict to rows whose tenant matches
        OR whose tenant is NULL. The NULL allowance keeps legacy /
        orphaned rows visible — see ``shared.lib.tenant_scope`` for
        the rationale.
        """
        if tenant_id is None:
            return sa.true()
        return sa.or_(tenant_column == tenant_id, tenant_column.is_(None))

    async def search_projects_by_name(
        self,
        user_id: int,
        name_query: str,
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> List[db_models.Project]:
        """Searches for projects by name within the caller's visibility."""
        stmt = (
            select(db_models.Project)
            .where(
                self._scope_column(db_models.Project.user_id, user_id, visible_user_ids)
            )
            .where(self._scope_tenant(db_models.Project.tenant_id, tenant_id))
            .where(db_models.Project.name.ilike(f"%{name_query}%"))
            .order_by(db_models.Project.name)
            .limit(10)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_scans_count_for_user(
        self,
        user_id: int,
        search: Optional[str],
        statuses: Optional[List[str]] = None,
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> int:
        """Counts the total number of scans the caller can see."""
        stmt = (
            select(func.count(db_models.Scan.id))
            .join(db_models.Scan.project)
            .where(
                self._scope_column(db_models.Scan.user_id, user_id, visible_user_ids)
            )
            .where(self._scope_tenant(db_models.Scan.tenant_id, tenant_id))
        )
        if search:
            search_term = f"%{search}%"
            stmt = stmt.where(
                or_(
                    cast(db_models.Scan.id, String).ilike(search_term),
                    db_models.Project.name.ilike(search_term),
                    db_models.Scan.status.ilike(search_term),
                    db_models.Scan.scan_type.ilike(search_term),
                )
            )
        if statuses:
            stmt = stmt.where(db_models.Scan.status.in_(statuses))

        result = await self.db.execute(stmt)
        return result.scalar_one() or 0

    async def get_paginated_scans_for_user(
        self,
        user_id: int,
        skip: int,
        limit: int,
        search: Optional[str],
        sort_order: str,
        statuses: Optional[List[str]] = None,
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> List[db_models.Scan]:
        """Retrieves a paginated list of scans the caller can see."""
        limit = max(1, min(int(limit), _MAX_PAGE_LIMIT))
        stmt = (
            select(db_models.Scan)
            .join(db_models.Scan.project)
            .options(
                selectinload(db_models.Scan.events),
                selectinload(db_models.Scan.project),
            )
            .where(
                self._scope_column(db_models.Scan.user_id, user_id, visible_user_ids)
            )
            .where(self._scope_tenant(db_models.Scan.tenant_id, tenant_id))
        )
        if search:
            search_term = f"%{search}%"
            stmt = stmt.where(
                or_(
                    cast(db_models.Scan.id, String).ilike(search_term),
                    db_models.Project.name.ilike(search_term),
                    db_models.Scan.status.ilike(search_term),
                    db_models.Scan.scan_type.ilike(search_term),
                )
            )

        if statuses:
            stmt = stmt.where(db_models.Scan.status.in_(statuses))

        order_column = db_models.Scan.created_at
        if sort_order.lower() == "asc":
            stmt = stmt.order_by(order_column.asc())
        else:
            stmt = stmt.order_by(order_column.desc())

        stmt = stmt.offset(skip).limit(limit)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_paginated_projects(
        self,
        user_id: int,
        skip: int,
        limit: int,
        search: Optional[str],
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> List[db_models.Project]:
        """Retrieves a paginated list of projects the caller can see."""
        limit = max(1, min(int(limit), _MAX_PAGE_LIMIT))
        stmt = (
            select(db_models.Project)
            .options(
                selectinload(db_models.Project.scans).joinedload(db_models.Scan.user)
            )
            .where(
                self._scope_column(db_models.Project.user_id, user_id, visible_user_ids)
            )
            .where(self._scope_tenant(db_models.Project.tenant_id, tenant_id))
        )
        if search:
            stmt = stmt.filter(db_models.Project.name.ilike(f"%{search}%"))
        stmt = (
            stmt.order_by(db_models.Project.updated_at.desc()).offset(skip).limit(limit)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_projects_count(
        self,
        user_id: int,
        search: Optional[str],
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> int:
        """Counts the total number of projects the caller can see."""
        stmt = (
            select(func.count(db_models.Project.id))
            .where(
                self._scope_column(db_models.Project.user_id, user_id, visible_user_ids)
            )
            .where(self._scope_tenant(db_models.Project.tenant_id, tenant_id))
        )
        if search:
            stmt = stmt.filter(db_models.Project.name.ilike(f"%{search}%"))
        result = await self.db.execute(stmt)
        return result.scalar_one() or 0

    async def get_llm_interactions_for_scan(
        self, scan_id: uuid.UUID
    ) -> List[db_models.LLMInteraction]:
        """Retrieves all LLM interactions for a specific scan."""
        stmt = (
            select(db_models.LLMInteraction)
            .where(db_models.LLMInteraction.scan_id == scan_id)
            .order_by(db_models.LLMInteraction.timestamp.asc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_source_files_by_hashes(
        self, file_hashes: List[str]
    ) -> Dict[str, str]:
        """Retrieves a dictionary of file content keyed by their hashes."""
        if not file_hashes:
            return {}
        stmt = select(db_models.SourceCodeFile).where(
            db_models.SourceCodeFile.hash.in_(file_hashes)
        )
        result = await self.db.execute(stmt)
        return {file.hash: file.content for file in result.scalars().all()}

    async def delete_scan(self, scan_id: uuid.UUID) -> bool:
        """Deletes a scan record from the database.

        Explicitly purges orphaned LLMInteraction rows before deleting the
        scan to avoid FK violations when ondelete=CASCADE is absent on
        LLMInteraction.scan_id (V14.2.7).
        """
        scan = await self.db.get(db_models.Scan, scan_id)
        if scan:
            await self.db.execute(
                delete(db_models.LLMInteraction).where(
                    db_models.LLMInteraction.scan_id == scan_id
                )
            )
            await self.db.delete(scan)
            try:
                await self.db.commit()
            except SQLAlchemyError as e:
                logger.error(
                    "scan_repo.delete_scan.commit_failed",
                    extra={
                        "scan_id": str(scan_id),
                        "error_class": e.__class__.__name__,
                    },
                    exc_info=True,
                )
                raise
            return True
        return False

    async def delete_project(self, project_id: uuid.UUID) -> bool:
        """Deletes a project record and its cascade-deleted scans.

        Explicitly purges LLMInteraction rows for all scans belonging to
        the project before deleting, to avoid FK violations when
        ondelete=CASCADE is absent on LLMInteraction.scan_id (V14.2.7).
        """
        project = await self.db.get(db_models.Project, project_id)
        if project:
            # Collect scan IDs then purge orphaned LLM interactions
            scan_ids_result = await self.db.execute(
                select(db_models.Scan.id).where(db_models.Scan.project_id == project_id)
            )
            scan_ids = [row[0] for row in scan_ids_result.all()]
            if scan_ids:
                await self.db.execute(
                    delete(db_models.LLMInteraction).where(
                        db_models.LLMInteraction.scan_id.in_(scan_ids)
                    )
                )
            await self.db.delete(project)
            try:
                await self.db.commit()
            except SQLAlchemyError as e:
                logger.error(
                    "scan_repo.delete_project.commit_failed",
                    extra={
                        "project_id": str(project_id),
                        "error_class": e.__class__.__name__,
                    },
                    exc_info=True,
                )
                raise
            return True
        return False
