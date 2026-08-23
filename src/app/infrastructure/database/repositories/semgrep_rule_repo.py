# src/app/infrastructure/database/repositories/semgrep_rule_repo.py
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select, func, and_, or_, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, selectinload

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class SemgrepRuleRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Source CRUD
    # ------------------------------------------------------------------

    async def list_sources(self) -> List[db_models.SemgrepRuleSource]:
        result = await self.db.execute(
            select(db_models.SemgrepRuleSource).order_by(
                db_models.SemgrepRuleSource.display_name
            )
        )
        return list(result.scalars().all())

    async def get_source_by_id(
        self, source_id: uuid.UUID
    ) -> Optional[db_models.SemgrepRuleSource]:
        result = await self.db.execute(
            select(db_models.SemgrepRuleSource).where(
                db_models.SemgrepRuleSource.id == source_id
            )
        )
        return result.scalars().first()

    async def get_source_by_slug(
        self, slug: str
    ) -> Optional[db_models.SemgrepRuleSource]:
        result = await self.db.execute(
            select(db_models.SemgrepRuleSource).where(
                db_models.SemgrepRuleSource.slug == slug
            )
        )
        return result.scalars().first()

    async def upsert_source(self, data: dict) -> db_models.SemgrepRuleSource:
        """Insert-or-update a source by slug. Does not overwrite enabled/auto_sync on existing rows."""
        existing = await self.get_source_by_slug(data["slug"])
        if existing:
            # Update mutable metadata fields; never touch enabled/auto_sync/sync_cron
            for field in (
                "display_name",
                "description",
                "repo_url",
                "branch",
                "subpath",
                "license_spdx",
                "author",
            ):
                if field in data:
                    setattr(existing, field, data[field])
            await self.db.flush()
            return existing

        source = db_models.SemgrepRuleSource(**data)
        self.db.add(source)
        await self.db.flush()
        return source

    async def update_source(
        self, source_id: uuid.UUID, updates: dict
    ) -> Optional[db_models.SemgrepRuleSource]:
        source = await self.get_source_by_id(source_id)
        if not source:
            return None
        allowed = {
            "display_name",
            "description",
            "repo_url",
            "branch",
            "subpath",
            "license_spdx",
            "author",
            "sync_cron",
            "enabled",
            "auto_sync",
        }
        for k, v in updates.items():
            if k in allowed:
                setattr(source, k, v)
        await self.db.flush()
        return source

    async def delete_source(self, source_id: uuid.UUID) -> bool:
        source = await self.get_source_by_id(source_id)
        if not source:
            return False
        await self.db.delete(source)
        await self.db.flush()
        return True

    # ------------------------------------------------------------------
    # Rule operations
    # ------------------------------------------------------------------

    async def upsert_rule(
        self, source_id: uuid.UUID, data: dict
    ) -> tuple[db_models.SemgrepRule, bool]:
        """Upsert a rule by namespaced_id. Returns (rule, is_new)."""
        result = await self.db.execute(
            select(db_models.SemgrepRule).where(
                db_models.SemgrepRule.namespaced_id == data["namespaced_id"]
            )
        )
        existing = result.scalars().first()
        if existing:
            if existing.content_hash != data.get("content_hash"):
                for k, v in data.items():
                    setattr(existing, k, v)
                existing.source_id = source_id
                await self.db.flush()
                return existing, False  # updated
            return existing, False  # unchanged

        rule = db_models.SemgrepRule(source_id=source_id, **data)
        self.db.add(rule)
        await self.db.flush()
        return rule, True

    async def list_rules(
        self,
        source_id: uuid.UUID,
        lang: Optional[str] = None,
        severity: Optional[str] = None,
        q: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[List[db_models.SemgrepRule], int]:
        stmt = select(db_models.SemgrepRule).where(
            db_models.SemgrepRule.source_id == source_id
        )
        if lang:
            stmt = stmt.where(db_models.SemgrepRule.languages.contains([lang]))
        if severity:
            stmt = stmt.where(db_models.SemgrepRule.severity == severity.upper())
        if q:
            stmt = stmt.where(
                or_(
                    db_models.SemgrepRule.namespaced_id.ilike(f"%{q}%"),
                    db_models.SemgrepRule.message.ilike(f"%{q}%"),
                )
            )
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar_one()
        stmt = stmt.order_by(
            db_models.SemgrepRule.severity.desc(), db_models.SemgrepRule.namespaced_id
        )
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        rows = list((await self.db.execute(stmt)).scalars().all())
        return rows, total

    async def get_rules_by_namespaced_ids(
        self, namespaced_ids: list[str]
    ) -> List[db_models.SemgrepRule]:
        """Load exact rule identities without applying mutable live selection.

        Callers must separately validate source/rule enablement and bind every
        returned body to immutable scan provenance before materialization.
        """
        if not namespaced_ids:
            return []
        result = await self.db.execute(
            select(db_models.SemgrepRule)
            .options(selectinload(db_models.SemgrepRule.source))
            .where(db_models.SemgrepRule.namespaced_id.in_(namespaced_ids))
        )
        return list(result.scalars().all())

    async def delete_rules_not_in(
        self, source_id: uuid.UUID, keep_namespaced_ids: set[str]
    ) -> int:
        """Delete rules for this source that are no longer present in the upstream repo."""
        if not keep_namespaced_ids:
            # Safety: if the set is empty, don't delete everything — the sync
            # probably produced 0 valid rules due to an error.
            return 0
        result = await self.db.execute(
            select(db_models.SemgrepRule).where(
                and_(
                    db_models.SemgrepRule.source_id == source_id,
                    db_models.SemgrepRule.namespaced_id.not_in(keep_namespaced_ids),
                )
            )
        )
        stale = result.scalars().all()
        for rule in stale:
            await self.db.delete(rule)
        await self.db.flush()
        return len(stale)

    async def select_rules_for_scan(
        self,
        languages: List[str],
        technologies: List[str],
        allowed_licenses: List[str],
        max_rules: int = 5000,
    ) -> List[db_models.SemgrepRule]:
        """
        Return enabled rules that:
        - belong to an enabled source
        - have license in allowed_licenses
        - language array overlaps requested languages
        - technology array either overlaps requested technologies OR is empty
        """
        if not languages:
            return []

        # Join with source to filter enabled sources
        src = aliased(db_models.SemgrepRuleSource)

        stmt = (
            select(db_models.SemgrepRule)
            .options(selectinload(db_models.SemgrepRule.source))
            .join(src, db_models.SemgrepRule.source_id == src.id)
            .where(
                and_(
                    src.enabled.is_(True),
                    db_models.SemgrepRule.enabled.is_(True),
                    db_models.SemgrepRule.license_spdx.in_(allowed_licenses),
                    # languages && requested (Postgres array overlap)
                    db_models.SemgrepRule.languages.overlap(languages),
                )
            )
        )
        if technologies:
            stmt = stmt.where(
                or_(
                    db_models.SemgrepRule.technology.overlap(technologies),
                    db_models.SemgrepRule.technology == [],
                )
            )
        # Severity ordering: ERROR → WARNING → INFO
        stmt = stmt.order_by(
            func.array_position(
                text("ARRAY['ERROR','WARNING','INFO']"),
                db_models.SemgrepRule.severity,
            )
        ).limit(max_rules)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_coverage_summary(
        self, languages: List[str], allowed_licenses: List[str]
    ) -> dict:
        """
        For each requested language, determine whether covered rules exist and
        which sources could provide coverage.
        Returns {lang: {covered: bool, enabled_rule_count: int, recommended_sources: [...]}}
        """
        from sqlalchemy.orm import aliased

        src = aliased(db_models.SemgrepRuleSource)

        summary: dict = {}
        for lang in languages:
            # Count currently active rules for this language
            count_stmt = (
                select(func.count())
                .select_from(db_models.SemgrepRule)
                .join(src, db_models.SemgrepRule.source_id == src.id)
                .where(
                    and_(
                        src.enabled.is_(True),
                        db_models.SemgrepRule.enabled.is_(True),
                        db_models.SemgrepRule.license_spdx.in_(allowed_licenses),
                        db_models.SemgrepRule.languages.contains([lang]),
                    )
                )
            )
            count = (await self.db.execute(count_stmt)).scalar_one()

            # Find disabled sources that have rules for this language (recommendations)
            rec_stmt = (
                select(db_models.SemgrepRuleSource)
                .join(
                    db_models.SemgrepRule,
                    db_models.SemgrepRule.source_id == db_models.SemgrepRuleSource.id,
                )
                .where(
                    and_(
                        db_models.SemgrepRuleSource.enabled.is_(False),
                        db_models.SemgrepRule.languages.contains([lang]),
                    )
                )
                .distinct()
                .limit(5)
            )
            rec_rows = list((await self.db.execute(rec_stmt)).scalars().all())

            summary[lang] = {
                "covered": count > 0,
                "enabled_rule_count": count,
                "recommended_sources": rec_rows,
            }
        return summary

    # ------------------------------------------------------------------
    # Sync run operations
    # ------------------------------------------------------------------

    async def create_sync_run(
        self, source_id: uuid.UUID, triggered_by: str
    ) -> db_models.SemgrepSyncRun:
        run = db_models.SemgrepSyncRun(source_id=source_id, triggered_by=triggered_by)
        self.db.add(run)
        await self.db.flush()
        return run

    async def update_sync_run(
        self, run_id: uuid.UUID, updates: dict
    ) -> Optional[db_models.SemgrepSyncRun]:
        result = await self.db.execute(
            select(db_models.SemgrepSyncRun).where(
                db_models.SemgrepSyncRun.id == run_id
            )
        )
        run = result.scalars().first()
        if not run:
            return None
        for k, v in updates.items():
            setattr(run, k, v)
        await self.db.flush()
        return run

    async def list_sync_runs(
        self, source_id: uuid.UUID, page: int = 1, page_size: int = 20
    ) -> tuple[List[db_models.SemgrepSyncRun], int]:
        count_stmt = select(func.count()).where(
            db_models.SemgrepSyncRun.source_id == source_id
        )
        total = (await self.db.execute(count_stmt)).scalar_one()
        stmt = (
            select(db_models.SemgrepSyncRun)
            .where(db_models.SemgrepSyncRun.source_id == source_id)
            .order_by(db_models.SemgrepSyncRun.started_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        rows = list((await self.db.execute(stmt)).scalars().all())
        return rows, total

    async def reset_stuck_runs(self) -> int:
        """On startup: mark any 'running' sync_runs as 'failed' (interrupted by restart)."""
        result = await self.db.execute(
            select(db_models.SemgrepSyncRun).where(
                db_models.SemgrepSyncRun.status == "running"
            )
        )
        stuck = result.scalars().all()
        now = datetime.now(tz=timezone.utc)
        for run in stuck:
            run.status = "failed"
            run.finished_at = now
            run.error = "Interrupted by application restart"
        await self.db.flush()
        if stuck:
            logger.warning(
                "semgrep_rule_repo.reset_stuck_runs",
                extra={"count": len(stuck)},
            )
        return len(stuck)

    async def get_latest_sync_run(
        self, source_id: uuid.UUID
    ) -> Optional[db_models.SemgrepSyncRun]:
        result = await self.db.execute(
            select(db_models.SemgrepSyncRun)
            .where(db_models.SemgrepSyncRun.source_id == source_id)
            .order_by(db_models.SemgrepSyncRun.started_at.desc())
            .limit(1)
        )
        return result.scalars().first()
