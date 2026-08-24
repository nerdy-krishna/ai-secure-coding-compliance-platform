"""Bounded, tenant-first reads over the canonical LLM usage ledger."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Literal, Sequence

import sqlalchemy as sa
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.infrastructure.database import models as db_models


@dataclass(frozen=True)
class UsageQuery:
    tenant_id: uuid.UUID
    from_at: datetime
    to_at: datetime
    visible_user_ids: tuple[int, ...] | None
    user_id: int | None = None
    group_id: uuid.UUID | None = None
    project_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None
    operation_kind: str | None = None
    operation_id: str | None = None
    stage: str | None = None
    agent_name: str | None = None
    provider: str | None = None
    model: str | None = None
    llm_config_id: uuid.UUID | None = None
    cost_status: str | None = None


_ZERO = Decimal("0")


class UsageCenterRepository:
    """Read model kept separate from append-only ledger persistence."""

    def __init__(self, db: AsyncSession):
        self.db = db

    def _event_clauses(self, query: UsageQuery) -> list[sa.ColumnElement[bool]]:
        event = db_models.LLMUsageEvent
        clauses: list[sa.ColumnElement[bool]] = [
            event.tenant_id == query.tenant_id,
            event.created_at >= query.from_at,
            event.created_at < query.to_at,
        ]
        if query.visible_user_ids is not None:
            clauses.append(event.user_id.in_(query.visible_user_ids))
        if query.user_id is not None:
            clauses.append(event.user_id == query.user_id)
        if query.group_id is not None:
            clauses.append(event.group_ids.any(query.group_id))
        if query.scan_id is not None:
            clauses.append(event.scan_id == query.scan_id)
        if query.operation_kind is not None:
            clauses.append(event.operation_kind == query.operation_kind)
        if query.operation_id is not None:
            clauses.append(event.operation_id == query.operation_id)
        if query.stage is not None:
            clauses.append(event.stage == query.stage)
        if query.agent_name is not None:
            clauses.append(event.agent_name == query.agent_name)
        if query.provider is not None:
            clauses.append(event.provider == query.provider)
        if query.model is not None:
            clauses.append(
                sa.or_(
                    event.requested_model == query.model,
                    event.resolved_models.any(query.model),
                )
            )
        if query.llm_config_id is not None:
            clauses.append(event.llm_config_id == query.llm_config_id)
        if query.cost_status is not None:
            clauses.append(event.cost_status == query.cost_status)
        if query.project_id is not None:
            clauses.append(
                event.scan_id.in_(
                    select(db_models.Scan.id).where(
                        db_models.Scan.project_id == query.project_id,
                        db_models.Scan.tenant_id == query.tenant_id,
                    )
                )
            )
        return clauses

    def _reservation_clauses(
        self, query: UsageQuery
    ) -> list[sa.ColumnElement[bool]]:
        reservation = db_models.UsageBudgetReservation
        clauses: list[sa.ColumnElement[bool]] = [
            reservation.tenant_id == query.tenant_id,
            reservation.created_at >= query.from_at,
            reservation.created_at < query.to_at,
        ]
        if query.visible_user_ids is not None:
            clauses.append(reservation.actor_user_id.in_(query.visible_user_ids))
        if query.user_id is not None:
            clauses.append(reservation.actor_user_id == query.user_id)
        if query.group_id is not None:
            clauses.append(reservation.group_ids.any(query.group_id))
        if query.operation_kind is not None:
            clauses.append(reservation.operation_kind == query.operation_kind)
        if query.stage is not None:
            clauses.append(reservation.stage == query.stage)
        if query.llm_config_id is not None:
            clauses.append(reservation.llm_config_id == query.llm_config_id)
        # Filters unavailable at reservation time fail closed rather than
        # attributing an estimate to the wrong provider/project/model.
        if any(
            value is not None
            for value in (
                query.project_id,
                query.scan_id,
                query.operation_id,
                query.agent_name,
                query.provider,
                query.model,
                query.cost_status,
            )
        ):
            clauses.append(sa.false())
        return clauses

    @staticmethod
    def _event_aggregates() -> list[sa.ColumnElement]:
        event = db_models.LLMUsageEvent
        actual = case(
            (
                event.cost_status.in_(("exact", "reconciled")),
                func.coalesce(event.total_cost, _ZERO),
            ),
            else_=_ZERO,
        )
        estimated = case(
            (
                event.cost_status == "estimated",
                func.coalesce(event.total_cost, _ZERO),
            ),
            else_=_ZERO,
        )
        reconciled = case(
            (
                event.cost_status == "reconciled",
                func.coalesce(event.total_cost, _ZERO),
            ),
            else_=_ZERO,
        )
        return [
            func.coalesce(func.sum(actual), _ZERO).label("actual_cost"),
            func.coalesce(func.sum(estimated), _ZERO).label("event_estimated_cost"),
            func.coalesce(func.sum(reconciled), _ZERO).label("reconciled_cost"),
            func.coalesce(func.sum(event.input_tokens), 0).label("input_tokens"),
            func.coalesce(func.sum(event.output_tokens), 0).label("output_tokens"),
            func.coalesce(func.sum(event.total_tokens), 0).label("total_tokens"),
            func.coalesce(func.sum(event.cache_read_tokens), 0).label("cache_read_tokens"),
            func.coalesce(func.sum(event.cache_write_tokens), 0).label("cache_write_tokens"),
            func.coalesce(func.sum(event.reasoning_tokens), 0).label("reasoning_tokens"),
            func.coalesce(func.sum(event.request_count), 0).label("requests"),
            func.count(event.id).label("events"),
            func.count(event.id).filter(event.cost_status == "unknown").label("unknown_events"),
            func.count(event.id).filter(event.cost_status == "estimated").label("estimated_events"),
            func.count(event.id).filter(event.cost_status == "reconciled").label("reconciled_events"),
        ]

    @staticmethod
    def _reservation_aggregates() -> list[sa.ColumnElement]:
        reservation = db_models.UsageBudgetReservation
        return [
            func.coalesce(func.sum(reservation.estimated_usd), _ZERO).label(
                "reservation_estimated_cost"
            ),
            func.coalesce(
                func.sum(reservation.estimated_usd).filter(
                    reservation.state == "held"
                ),
                _ZERO,
            ).label("reserved_cost"),
            func.coalesce(
                func.sum(reservation.estimated_provider_requests).filter(
                    reservation.state == "held"
                ),
                0,
            ).label("reserved_requests"),
        ]

    async def summary(self, query: UsageQuery) -> tuple[sa.Row, sa.Row]:
        event_row = (
            await self.db.execute(
                select(*self._event_aggregates()).where(*self._event_clauses(query))
            )
        ).one()
        reservation_row = (
            await self.db.execute(
                select(*self._reservation_aggregates()).where(
                    *self._reservation_clauses(query)
                )
            )
        ).one()
        return event_row, reservation_row

    async def trends(
        self,
        query: UsageQuery,
        *,
        interval: Literal["hour", "day", "week", "month"],
    ) -> tuple[list[sa.Row], list[sa.Row]]:
        event_bucket = func.date_trunc(
            interval, db_models.LLMUsageEvent.created_at
        ).label("bucket")
        event_rows = (
            await self.db.execute(
                select(event_bucket, *self._event_aggregates())
                .where(*self._event_clauses(query))
                .group_by(event_bucket)
                .order_by(event_bucket)
            )
        ).all()
        reservation_bucket = func.date_trunc(
            interval, db_models.UsageBudgetReservation.created_at
        ).label("bucket")
        reservation_rows = (
            await self.db.execute(
                select(reservation_bucket, *self._reservation_aggregates())
                .where(*self._reservation_clauses(query))
                .group_by(reservation_bucket)
                .order_by(reservation_bucket)
            )
        ).all()
        return list(event_rows), list(reservation_rows)

    def _breakdown_key(self, dimension: str) -> sa.ColumnElement:
        event = db_models.LLMUsageEvent
        if dimension == "operation":
            return event.operation_kind
        if dimension == "scan":
            return sa.cast(event.scan_id, sa.String)
        if dimension == "stage":
            return event.stage
        if dimension == "agent":
            return event.agent_name
        if dimension == "provider":
            return event.provider
        if dimension == "model":
            return event.requested_model
        if dimension == "account":
            return sa.cast(event.user_id, sa.String)
        if dimension == "project":
            return sa.cast(db_models.Scan.project_id, sa.String)
        if dimension == "group":
            raise ValueError("group breakdown requires a lateral source")
        raise ValueError("unsupported usage breakdown dimension")

    async def breakdown(
        self,
        query: UsageQuery,
        *,
        dimension: str,
        page: int,
        page_size: int,
    ) -> tuple[list[sa.Row], int]:
        if dimension == "group":
            groups = (
                func.unnest(db_models.LLMUsageEvent.group_ids)
                .table_valued("group_id")
                .render_derived(name="usage_groups")
                .lateral()
            )
            key = sa.cast(groups.c.group_id, sa.String)
            base = (
                select(key.label("key"), *self._event_aggregates())
                .select_from(db_models.LLMUsageEvent)
                .join(groups, sa.true())
            )
        else:
            key = self._breakdown_key(dimension)
            base = select(key.label("key"), *self._event_aggregates())
        if dimension == "project":
            base = base.select_from(db_models.LLMUsageEvent).join(
                db_models.Scan,
                sa.and_(
                    db_models.Scan.id == db_models.LLMUsageEvent.scan_id,
                    db_models.Scan.tenant_id == db_models.LLMUsageEvent.tenant_id,
                ),
                isouter=True,
            )
        grouped = (
            base.where(*self._event_clauses(query), key.is_not(None))
            .group_by(key)
        )
        count = int(
            await self.db.scalar(select(func.count()).select_from(grouped.subquery()))
            or 0
        )
        rows = (
            await self.db.execute(
                grouped.order_by(sa.desc("actual_cost"), key)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
        return list(rows), count

    async def list_events(
        self,
        query: UsageQuery,
        *,
        limit: int,
        before: tuple[datetime, uuid.UUID] | None = None,
    ) -> list[db_models.LLMUsageEvent]:
        event = db_models.LLMUsageEvent
        stmt = select(event).where(*self._event_clauses(query))
        if before is not None:
            stmt = stmt.where(sa.tuple_(event.created_at, event.id) < before)
        return list(
            (
                await self.db.scalars(
                    stmt.order_by(event.created_at.desc(), event.id.desc()).limit(limit)
                )
            ).all()
        )

    async def current_budget_rows(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: int,
        group_ids: Sequence[uuid.UUID],
        tenant_wide: bool,
        at: datetime,
    ) -> list[tuple[db_models.UsageBudgetPolicy, db_models.UsageBudgetCounter | None]]:
        policy = db_models.UsageBudgetPolicy
        counter = db_models.UsageBudgetCounter
        newer = aliased(db_models.UsageBudgetPolicy)
        target = policy.scope_kind == "tenant"
        if not tenant_wide:
            target = sa.or_(
                target,
                sa.and_(policy.scope_kind == "user", policy.target_user_id == user_id),
                sa.and_(
                    policy.scope_kind == "group",
                    policy.target_group_id.in_(tuple(group_ids) or (uuid.UUID(int=0),)),
                ),
            )
        rows = (
            await self.db.execute(
                select(policy, counter)
                .outerjoin(
                    counter,
                    sa.and_(
                        counter.policy_id == policy.id,
                        counter.window_start <= at,
                        counter.window_end > at,
                    ),
                )
                .where(
                    policy.tenant_id == tenant_id,
                    policy.enabled.is_(True),
                    policy.effective_from <= at,
                    sa.or_(policy.effective_to.is_(None), policy.effective_to > at),
                    ~sa.exists(
                        select(newer.id).where(
                            newer.logical_policy_id == policy.logical_policy_id,
                            newer.version > policy.version,
                            newer.effective_from <= at,
                        )
                    ),
                    target,
                )
                .order_by(policy.scope_kind, policy.window_kind, policy.created_at.desc())
            )
        ).all()
        return [(row[0], row[1]) for row in rows]

    async def recent_thresholds(
        self, *, tenant_id: uuid.UUID, policy_ids: Sequence[uuid.UUID], limit: int = 20
    ) -> list[db_models.UsageBudgetThresholdEvent]:
        if not policy_ids:
            return []
        return list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetThresholdEvent)
                    .where(
                        db_models.UsageBudgetThresholdEvent.tenant_id == tenant_id,
                        db_models.UsageBudgetThresholdEvent.policy_id.in_(policy_ids),
                    )
                    .order_by(db_models.UsageBudgetThresholdEvent.created_at.desc())
                    .limit(limit)
                )
            ).all()
        )

    async def recent_budget_exhausted_scans(
        self,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: tuple[int, ...] | None,
        limit: int = 20,
    ) -> list[db_models.Scan]:
        stmt = select(db_models.Scan).where(
            db_models.Scan.tenant_id == tenant_id,
            db_models.Scan.status == "BUDGET_EXHAUSTED",
        )
        if visible_user_ids is not None:
            stmt = stmt.where(db_models.Scan.user_id.in_(visible_user_ids))
        return list(
            (
                await self.db.scalars(
                    stmt.order_by(
                        func.coalesce(
                            db_models.Scan.completed_at, db_models.Scan.created_at
                        ).desc()
                    ).limit(limit)
                )
            ).all()
        )

    async def recent_budget_denials(
        self,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: tuple[int, ...] | None,
        limit: int = 20,
    ) -> list[db_models.AuthorizationAuditEvent]:
        event = db_models.AuthorizationAuditEvent
        stmt = select(event).where(
            event.tenant_id == tenant_id,
            event.permission == "usage.consume",
            event.outcome == "denied",
            event.reason_code.in_(
                ("budget_hard_limit_exceeded", "budget_price_unknown")
            ),
        )
        if visible_user_ids is not None:
            stmt = stmt.where(
                event.principal_kind == "human",
                event.principal_id.in_(tuple(str(value) for value in visible_user_ids)),
            )
        return list(
            (
                await self.db.scalars(
                    stmt.order_by(event.occurred_at.desc()).limit(limit)
                )
            ).all()
        )

    async def user_group_ids(
        self, *, tenant_id: uuid.UUID, user_id: int, owner_only: bool = False
    ) -> list[uuid.UUID]:
        membership = db_models.UserGroupMembership
        stmt = (
            select(membership.group_id)
            .join(db_models.UserGroup, db_models.UserGroup.id == membership.group_id)
            .where(
                membership.user_id == user_id,
                db_models.UserGroup.tenant_id == tenant_id,
            )
        )
        if owner_only:
            stmt = stmt.where(membership.role == "owner")
        return list((await self.db.scalars(stmt.order_by(membership.group_id))).all())

    async def group_user_ids(
        self, *, tenant_id: uuid.UUID, group_ids: Sequence[uuid.UUID]
    ) -> list[int]:
        if not group_ids:
            return []
        return list(
            (
                await self.db.scalars(
                    select(db_models.UserGroupMembership.user_id)
                    .join(
                        db_models.UserGroup,
                        db_models.UserGroup.id
                        == db_models.UserGroupMembership.group_id,
                    )
                    .where(
                        db_models.UserGroupMembership.group_id.in_(group_ids),
                        db_models.UserGroup.tenant_id == tenant_id,
                    )
                    .distinct()
                    .order_by(db_models.UserGroupMembership.user_id)
                )
            ).all()
        )

    async def policy_target_exists(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: int | None = None,
        group_id: uuid.UUID | None = None,
    ) -> bool:
        if user_id is not None:
            return (
                await self.db.scalar(
                    select(db_models.User.id).where(
                        db_models.User.id == user_id,
                        db_models.User.tenant_id == tenant_id,
                    )
                )
            ) is not None
        if group_id is not None:
            return (
                await self.db.scalar(
                    select(db_models.UserGroup.id).where(
                        db_models.UserGroup.id == group_id,
                        db_models.UserGroup.tenant_id == tenant_id,
                    )
                )
            ) is not None
        return True
