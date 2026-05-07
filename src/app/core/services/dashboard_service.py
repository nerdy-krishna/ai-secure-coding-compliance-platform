# src/app/core/services/dashboard_service.py
"""Dashboard aggregation service.

Powers `GET /api/v1/dashboard/stats`. One round-trip per metric against
the scans + findings + llm_interactions tables, scoped by
`visible_user_ids` (None for admins, list for users).

The shape is small and intentional: the UI just needs one risk number,
severity buckets, a 14-day scan trend, and a few counters. No pagination,
no per-scan detail — that's what `/scans/history` is for.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import sqlalchemy as sa
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.shared.lib.risk_score import (
    MAX_FINDINGS,
    compute_cvss_aggregate,
    to_posture_score,
)

logger = logging.getLogger(__name__)


SEVERITY_BUCKETS = ("critical", "high", "medium", "low", "informational")
_SEVERITY_ALIASES: Dict[str, str] = {
    "info": "informational",
    "informational": "informational",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


@dataclass(frozen=True, slots=True)
class _FindingRow:
    """Narrow projection of `findings` consumed by `compute_cvss_aggregate`.

    Selecting only these three columns keeps the row small (the
    aggregator never reads description/title/file_path, which are
    LLM-emitted from attacker-controlled code).
    """

    severity: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]


@dataclass
class DashboardStats:
    risk_score: int
    open_findings: Dict[str, int] = field(default_factory=dict)
    fixes_ready: int = 0
    scans_this_month: int = 0
    scans_trend: List[int] = field(default_factory=list)
    cost_this_month_usd: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "risk_score": self.risk_score,
            "open_findings": self.open_findings,
            "fixes_ready": self.fixes_ready,
            "scans_this_month": self.scans_this_month,
            "scans_trend": self.scans_trend,
            "cost_this_month_usd": round(self.cost_this_month_usd, 4),
        }


class DashboardService:
    """Computes the dashboard rollup for a given visibility scope."""

    # 14-day sparkline — two weeks is long enough to notice a trend, short
    # enough to fit on a dev dashboard without scrolling.
    TREND_DAYS = 14

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_stats(
        self,
        visible_user_ids: Optional[List[int]],
        tenant_id: Optional[uuid.UUID] = None,
    ) -> DashboardStats:
        try:
            scope_filter = self._scope_filter(visible_user_ids, tenant_id)

            open_findings = await self._open_findings_by_severity(scope_filter)
            fixes_ready = await self._fixes_ready(scope_filter)
            scans_this_month, scans_trend, cost_this_month = await self._scan_activity(
                scope_filter
            )
            rows = await self._findings_for_aggregate(scope_filter)
            # Off-thread so a large finding set does not stall the FastAPI
            # event loop while the cvss library iterates per-row.
            aggregate = await asyncio.to_thread(compute_cvss_aggregate, rows)
            risk_score = self._risk_score(aggregate)

            return DashboardStats(
                risk_score=risk_score,
                open_findings=open_findings,
                fixes_ready=fixes_ready,
                scans_this_month=scans_this_month,
                scans_trend=scans_trend,
                cost_this_month_usd=cost_this_month,
            )
        except Exception:
            logger.error(
                "dashboard: aggregate stats failed",
                extra={
                    "visible_user_ids": visible_user_ids,
                    "tenant_id": str(tenant_id) if tenant_id else None,
                },
                exc_info=True,
            )
            raise

    # --- internals -----------------------------------------------------

    @staticmethod
    def _scope_filter(
        visible_user_ids: Optional[List[int]],
        tenant_id: Optional[uuid.UUID] = None,
    ) -> sa.ColumnElement[bool]:
        """Translate a (visible_user_ids, tenant_id) pair into a SQL predicate
        anchored on the ``scans`` table.

        Tenant filtering follows the project-wide convention from
        ``shared.lib.tenant_scope``: ``None`` means "no filter" (admin
        passthrough), a UUID means "rows in this tenant OR rows whose
        tenant is NULL" (legacy / orphaned).
        """
        if visible_user_ids is None:
            user_pred: sa.ColumnElement[bool] = sa.true()
        elif not visible_user_ids:
            # Empty list shouldn't happen in practice (the caller always
            # prepends the requester's id) but is harmless: match nothing.
            user_pred = sa.false()
        else:
            user_pred = db_models.Scan.user_id.in_(visible_user_ids)

        if tenant_id is None:
            tenant_pred: sa.ColumnElement[bool] = sa.true()
        else:
            tenant_pred = sa.or_(
                db_models.Scan.tenant_id == tenant_id,
                db_models.Scan.tenant_id.is_(None),
            )
        return sa.and_(user_pred, tenant_pred)

    async def _open_findings_by_severity(
        self, scope_filter: sa.ColumnElement[bool]
    ) -> Dict[str, int]:
        stmt = (
            select(
                func.lower(db_models.Finding.severity).label("sev"),
                func.count(db_models.Finding.id),
            )
            .join(db_models.Scan, db_models.Scan.id == db_models.Finding.scan_id)
            .where(scope_filter)
            .where(db_models.Finding.is_applied_in_remediation.is_(False))
            .group_by(func.lower(db_models.Finding.severity))
        )
        rows = (await self.db.execute(stmt)).all()
        buckets: Dict[str, int] = {sev: 0 for sev in SEVERITY_BUCKETS}
        for raw_sev, count in rows:
            if raw_sev is None:
                continue
            key = _SEVERITY_ALIASES.get(raw_sev)
            if key:
                buckets[key] += int(count)
        return buckets

    async def _findings_for_aggregate(
        self, scope_filter: sa.ColumnElement[bool], limit: int = MAX_FINDINGS
    ) -> List[_FindingRow]:
        """Fetch the narrow projection that `compute_cvss_aggregate` reads.

        Pulled severity-desc with a `LIMIT` so a tenant with millions of
        findings cannot pin the API thread; the aggregator also caps at
        `MAX_FINDINGS` defensively. Only `severity`, `cvss_score`, and
        `cvss_vector` are selected — never description / file_path,
        which are LLM-emitted from attacker-controlled code.
        """
        severity_rank = case(
            (func.upper(db_models.Finding.severity) == "CRITICAL", 4),
            (func.upper(db_models.Finding.severity) == "HIGH", 3),
            (func.upper(db_models.Finding.severity) == "MEDIUM", 2),
            (func.upper(db_models.Finding.severity) == "LOW", 1),
            else_=0,
        )
        stmt = (
            select(
                db_models.Finding.severity,
                db_models.Finding.cvss_score,
                db_models.Finding.cvss_vector,
            )
            .join(db_models.Scan, db_models.Scan.id == db_models.Finding.scan_id)
            .where(scope_filter)
            .where(db_models.Finding.is_applied_in_remediation.is_(False))
            .order_by(severity_rank.desc())
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return [
            _FindingRow(severity=sev, cvss_score=score, cvss_vector=vec)
            for sev, score, vec in result.all()
        ]

    async def _fixes_ready(self, scope_filter: sa.ColumnElement[bool]) -> int:
        """Findings with an AI-suggested fix that hasn't been applied yet."""
        stmt = (
            select(func.count(db_models.Finding.id))
            .join(db_models.Scan, db_models.Scan.id == db_models.Finding.scan_id)
            .where(scope_filter)
            .where(db_models.Finding.fixes.is_not(None))
            .where(db_models.Finding.is_applied_in_remediation.is_(False))
        )
        return int((await self.db.execute(stmt)).scalar() or 0)

    async def _scan_activity(
        self, scope_filter: sa.ColumnElement[bool]
    ) -> tuple[int, List[int], float]:
        """Return (scans_this_month, last-14-day trend, cost_this_month_usd)."""
        now = datetime.now(timezone.utc)
        first_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        trend_start = (now - timedelta(days=self.TREND_DAYS - 1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        month_stmt = (
            select(func.count(db_models.Scan.id))
            .where(scope_filter)
            .where(db_models.Scan.created_at >= first_of_month)
        )
        scans_this_month = int((await self.db.execute(month_stmt)).scalar() or 0)

        # Daily buckets via date_trunc keeps the grouping inside Postgres.
        day_expr = func.date_trunc("day", db_models.Scan.created_at)
        trend_stmt = (
            select(day_expr.label("day"), func.count(db_models.Scan.id))
            .where(scope_filter)
            .where(db_models.Scan.created_at >= trend_start)
            .group_by(day_expr)
        )
        per_day = {
            row[0].date(): int(row[1])
            for row in (await self.db.execute(trend_stmt)).all()
        }
        trend: List[int] = []
        for i in range(self.TREND_DAYS):
            day = (trend_start + timedelta(days=i)).date()
            trend.append(per_day.get(day, 0))

        # Cost this month: aggregate `llm_interactions.cost` for interactions
        # whose parent scan was created this calendar month and is within the
        # visibility scope. `cost_details` on Scan is the pre-scan estimate;
        # real post-call costs are logged per LLM interaction.
        cost_stmt = (
            select(func.coalesce(func.sum(db_models.LLMInteraction.cost), 0))
            .join(
                db_models.Scan,
                db_models.Scan.id == db_models.LLMInteraction.scan_id,
            )
            .where(scope_filter)
            .where(db_models.Scan.created_at >= first_of_month)
        )
        cost_value = (await self.db.execute(cost_stmt)).scalar()
        cost_this_month = float(cost_value or 0.0)

        return scans_this_month, trend, cost_this_month

    @staticmethod
    def _risk_score(aggregate: float) -> int:
        """Map the unified 0.0-10.0 CVSS aggregate to the 0-100 posture
        scale. JSON shape is unchanged — clients still see an integer in
        ``[5, 100]`` where higher = healthier.
        """
        return to_posture_score(aggregate)
