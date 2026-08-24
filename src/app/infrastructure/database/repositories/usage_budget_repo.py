"""Tenant-scoped durable usage-budget policies, holds, and settlements."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal, Sequence

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.infrastructure.database import models as db_models
from app.config.logging_config import correlation_id_var
from app.infrastructure.database.repositories.llm_usage_repo import LLMUsageContext


DIMENSIONS = (
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "uncached_input_tokens",
    "billable_tokens",
    "usd",
    "provider_requests",
)


@dataclass(frozen=True)
class BudgetAmounts:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    uncached_input_tokens: int = 0
    billable_tokens: int = 0
    usd: Decimal = Decimal("0")
    provider_requests: int = 0

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if value < 0:
                raise ValueError(f"budget amount {field.name} must be non-negative")

    def as_model_values(self, prefix: str) -> dict[str, int | Decimal]:
        return {f"{prefix}_{name}": getattr(self, name) for name in DIMENSIONS}


@dataclass(frozen=True)
class BudgetAttribution:
    tenant_id: uuid.UUID
    actor_user_id: int | None
    group_ids: tuple[uuid.UUID, ...]
    scan_attempt_id: uuid.UUID | None


@dataclass(frozen=True)
class BudgetReservationRequest:
    tenant_id: uuid.UUID
    idempotency_key: str
    operation_kind: Literal["scan", "chat", "rag"]
    request_key: str
    stage: str
    estimate: BudgetAmounts
    expires_at: datetime
    actor_user_id: int | None = None
    group_ids: tuple[uuid.UUID, ...] = ()
    scan_attempt_id: uuid.UUID | None = None
    llm_config_id: uuid.UUID | None = None
    parent_reservation_id: uuid.UUID | None = None
    window_kinds: tuple[str, ...] = ("request", "scan", "day", "month")
    at: datetime | None = None


@dataclass(frozen=True)
class BudgetDenial:
    policy_id: uuid.UUID
    scope_kind: str
    window_kind: str
    dimension: str
    remaining: int | Decimal
    requested: int | Decimal
    reset_at: datetime | None


@dataclass(frozen=True)
class BudgetReservationDecision:
    allowed: bool
    reservation: db_models.UsageBudgetReservation | None = None
    denial: BudgetDenial | None = None
    replayed: bool = False


def utc_window(
    window_kind: str,
    *,
    at: datetime,
    request_key: str,
    scan_attempt_id: uuid.UUID | None,
    expires_at: datetime,
) -> tuple[str, datetime, datetime]:
    """Return the stable key and half-open UTC interval for a policy window."""
    current = at.astimezone(timezone.utc)
    if window_kind == "day":
        start = current.replace(hour=0, minute=0, second=0, microsecond=0)
        return start.strftime("day:%Y-%m-%d"), start, start + timedelta(days=1)
    if window_kind == "month":
        start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if start.month == 12:
            end = start.replace(year=start.year + 1, month=1)
        else:
            end = start.replace(month=start.month + 1)
        return start.strftime("month:%Y-%m"), start, end
    if window_kind == "request":
        return f"request:{request_key}", current, expires_at
    if window_kind == "scan":
        if scan_attempt_id is None:
            raise ValueError("scan-window policy requires a scan attempt")
        return f"scan:{scan_attempt_id}", current, expires_at
    raise ValueError(f"unsupported budget window: {window_kind}")


class UsageBudgetRepository:
    """Persistence boundary that serializes capacity checks in PostgreSQL."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_denial(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int | None,
        operation_kind: str,
        request_key: str,
        policy_id: uuid.UUID,
        reason_code: str,
        commit: bool,
    ) -> None:
        """Append a privacy-safe admission denial for affected-user views."""
        self.db.add(
            db_models.AuthorizationAuditEvent(
                tenant_id=tenant_id,
                principal_kind="human" if actor_user_id is not None else "system",
                principal_id=str(actor_user_id or "budget-worker"),
                permission="usage.consume",
                resource_type=f"usage_budget_{operation_kind}",
                target_fingerprint=hashlib.sha256(
                    f"{policy_id}:{request_key}".encode()
                ).hexdigest(),
                outcome="denied",
                reason_code=reason_code,
                correlation_id=correlation_id_var.get(),
            )
        )
        if commit:
            await self.db.commit()

    async def resolve_attribution(self, context: LLMUsageContext) -> BudgetAttribution:
        try:
            operation_id = uuid.UUID(str(context.operation_id))
        except ValueError as exc:
            raise ValueError("usage operation id must be a UUID") from exc

        if context.operation_kind == "scan":
            row = (
                await self.db.execute(
                    select(
                        db_models.Scan.tenant_id,
                        db_models.Scan.user_id,
                        db_models.Scan.current_attempt_id,
                    ).where(db_models.Scan.id == (context.scan_id or operation_id))
                )
            ).one_or_none()
        elif context.operation_kind == "chat":
            if context.chat_session_id is None and context.actor_user_id is not None:
                found = (
                    await self.db.execute(
                        select(db_models.User.tenant_id, db_models.User.id).where(
                            db_models.User.id == context.actor_user_id
                        )
                    )
                ).one_or_none()
            else:
                chat_id = context.chat_session_id or operation_id
                found = (
                    await self.db.execute(
                        select(
                            db_models.ChatSession.tenant_id,
                            db_models.ChatSession.user_id,
                        ).where(db_models.ChatSession.id == chat_id)
                    )
                ).one_or_none()
            row = (*found, None) if found is not None else None
        elif context.operation_kind == "rag":
            rag_id = context.rag_job_id or operation_id
            found = (
                await self.db.execute(
                    select(
                        db_models.User.tenant_id, db_models.RAGPreprocessingJob.user_id
                    )
                    .join(
                        db_models.User,
                        db_models.User.id == db_models.RAGPreprocessingJob.user_id,
                    )
                    .where(db_models.RAGPreprocessingJob.id == rag_id)
                )
            ).one_or_none()
            row = (*found, None) if found is not None else None
        else:  # pragma: no cover - Literal protects typed call sites
            raise ValueError(f"unsupported usage operation: {context.operation_kind}")
        if row is None:
            raise ValueError("usage operation not found in active tenant scope")

        tenant_id, owner_user_id, attempt_id = row
        actor_user_id = context.actor_user_id or owner_user_id
        if actor_user_id is not None:
            actor_tenant = await self.db.scalar(
                select(db_models.User.tenant_id).where(
                    db_models.User.id == actor_user_id
                )
            )
            if actor_tenant != tenant_id:
                raise ValueError("usage actor is outside the operation tenant")
            groups = tuple(
                (
                    await self.db.scalars(
                        select(db_models.UserGroupMembership.group_id)
                        .join(
                            db_models.UserGroup,
                            db_models.UserGroup.id
                            == db_models.UserGroupMembership.group_id,
                        )
                        .where(
                            db_models.UserGroupMembership.user_id == actor_user_id,
                            db_models.UserGroup.tenant_id == tenant_id,
                        )
                        .order_by(db_models.UserGroupMembership.group_id)
                    )
                ).all()
            )
        else:
            groups = ()
        return BudgetAttribution(tenant_id, actor_user_id, groups, attempt_id)

    async def list_policies(
        self, tenant_id: uuid.UUID, *, include_disabled: bool = False
    ) -> list[db_models.UsageBudgetPolicy]:
        query = select(db_models.UsageBudgetPolicy).where(
            db_models.UsageBudgetPolicy.tenant_id == tenant_id
        )
        if not include_disabled:
            effective_at = datetime.now(timezone.utc)
            newer = aliased(db_models.UsageBudgetPolicy)
            query = query.where(
                db_models.UsageBudgetPolicy.enabled.is_(True),
                db_models.UsageBudgetPolicy.effective_from <= effective_at,
                (
                    db_models.UsageBudgetPolicy.effective_to.is_(None)
                    | (db_models.UsageBudgetPolicy.effective_to > effective_at)
                ),
                ~sa.exists(
                    select(newer.id).where(
                        newer.logical_policy_id
                        == db_models.UsageBudgetPolicy.logical_policy_id,
                        newer.version > db_models.UsageBudgetPolicy.version,
                        newer.effective_from <= effective_at,
                    )
                ),
            )
        return list(
            (
                await self.db.scalars(
                    query.order_by(
                        db_models.UsageBudgetPolicy.logical_policy_id,
                        db_models.UsageBudgetPolicy.version.desc(),
                    )
                )
            ).all()
        )

    async def get_policy(
        self, policy_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> db_models.UsageBudgetPolicy | None:
        return await self.db.scalar(
            select(db_models.UsageBudgetPolicy).where(
                db_models.UsageBudgetPolicy.id == policy_id,
                db_models.UsageBudgetPolicy.tenant_id == tenant_id,
            )
        )

    async def list_active_policies(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: int | None,
        group_ids: Sequence[uuid.UUID],
        llm_config_id: uuid.UUID | None,
        stage: str,
        window_kinds: Sequence[str] | None = None,
        at: datetime | None = None,
    ) -> list[db_models.UsageBudgetPolicy]:
        effective_at = at or datetime.now(timezone.utc)
        newer = aliased(db_models.UsageBudgetPolicy)
        scope_predicates: list[Any] = [
            db_models.UsageBudgetPolicy.scope_kind == "tenant"
        ]
        if user_id is not None:
            scope_predicates.append(
                sa.and_(
                    db_models.UsageBudgetPolicy.scope_kind == "user",
                    db_models.UsageBudgetPolicy.target_user_id == user_id,
                )
            )
        if group_ids:
            scope_predicates.append(
                sa.and_(
                    db_models.UsageBudgetPolicy.scope_kind == "group",
                    db_models.UsageBudgetPolicy.target_group_id.in_(tuple(group_ids)),
                )
            )
        query = (
            select(db_models.UsageBudgetPolicy)
            .where(
                db_models.UsageBudgetPolicy.tenant_id == tenant_id,
                db_models.UsageBudgetPolicy.enabled.is_(True),
                db_models.UsageBudgetPolicy.effective_from <= effective_at,
                (
                    db_models.UsageBudgetPolicy.effective_to.is_(None)
                    | (db_models.UsageBudgetPolicy.effective_to > effective_at)
                ),
                (
                    db_models.UsageBudgetPolicy.llm_config_id.is_(None)
                    | (db_models.UsageBudgetPolicy.llm_config_id == llm_config_id)
                ),
                (
                    db_models.UsageBudgetPolicy.stage.is_(None)
                    | (db_models.UsageBudgetPolicy.stage == stage)
                ),
                sa.or_(*scope_predicates),
                ~sa.exists(
                    select(newer.id).where(
                        newer.logical_policy_id
                        == db_models.UsageBudgetPolicy.logical_policy_id,
                        newer.version > db_models.UsageBudgetPolicy.version,
                        newer.effective_from <= effective_at,
                    )
                ),
            )
            .order_by(db_models.UsageBudgetPolicy.id)
        )
        if window_kinds is not None:
            query = query.where(
                db_models.UsageBudgetPolicy.window_kind.in_(tuple(window_kinds))
            )
        return list((await self.db.scalars(query)).all())

    async def create_policy(
        self,
        *,
        tenant_id: uuid.UUID,
        scope_kind: Literal["tenant", "group", "user"],
        window_kind: Literal["request", "scan", "day", "month"],
        reason: str,
        created_by_user_id: int,
        target_group_id: uuid.UUID | None = None,
        target_user_id: int | None = None,
        llm_config_id: uuid.UUID | None = None,
        stage: str | None = None,
        cap_input_tokens: int | None = None,
        cap_output_tokens: int | None = None,
        cap_total_tokens: int | None = None,
        cap_uncached_input_tokens: int | None = None,
        cap_billable_tokens: int | None = None,
        cap_usd: Decimal | None = None,
        cap_provider_requests: int | None = None,
        soft_threshold_low: int = 80,
        soft_threshold_high: int = 95,
        unknown_price_action: Literal["deny", "token_only"] = "deny",
        enabled: bool = True,
        effective_from: datetime | None = None,
        effective_to: datetime | None = None,
        logical_policy_id: uuid.UUID | None = None,
        version: int = 1,
        commit: bool = True,
    ) -> db_models.UsageBudgetPolicy:
        values = locals().copy()
        values.pop("self")
        values.pop("commit")
        values["logical_policy_id"] = logical_policy_id or uuid.uuid4()
        values["effective_from"] = effective_from or datetime.now(timezone.utc)
        await self._validate_policy_values(**values)
        row = db_models.UsageBudgetPolicy(**values)
        self.db.add(row)
        await self.db.flush()
        if commit:
            await self.db.commit()
            await self.db.refresh(row)
        return row

    async def ensure_default_scan_policy(
        self,
        *,
        tenant_id: uuid.UUID,
        created_by_user_id: int,
        commit: bool = True,
    ) -> db_models.UsageBudgetPolicy:
        """Lazily establish the legacy-compatible $100 scan ceiling.

        The migration seeds tenants that already exist. New tenants receive the
        same deterministic policy when their first scan reaches a priced gate,
        avoiding unrelated tenant/user provisioning side effects.
        """
        logical_policy_id = uuid.UUID(
            hashlib.md5(
                f"{tenant_id}:default-scan-usd".encode(), usedforsecurity=False
            ).hexdigest()
        )
        await self.db.execute(
            pg_insert(db_models.UsageBudgetPolicy)
            .values(
                id=logical_policy_id,
                logical_policy_id=logical_policy_id,
                version=1,
                tenant_id=tenant_id,
                scope_kind="tenant",
                window_kind="scan",
                cap_usd=Decimal("100"),
                enabled=True,
                effective_from=datetime.now(timezone.utc),
                reason="System default preserving the legacy per-scan estimate ceiling",
                created_by_user_id=created_by_user_id,
            )
            .on_conflict_do_nothing(index_elements=["logical_policy_id", "version"])
        )
        policy = await self.db.scalar(
            select(db_models.UsageBudgetPolicy).where(
                db_models.UsageBudgetPolicy.logical_policy_id == logical_policy_id,
                db_models.UsageBudgetPolicy.version == 1,
            )
        )
        if policy is None:
            raise RuntimeError("default scan budget policy could not be established")
        if commit:
            await self.db.commit()
            await self.db.refresh(policy)
        return policy

    async def replace_policy(
        self,
        *,
        policy_id: uuid.UUID,
        tenant_id: uuid.UUID,
        created_by_user_id: int,
        reason: str,
        commit: bool = True,
        **changes: Any,
    ) -> db_models.UsageBudgetPolicy:
        current = await self.db.scalar(
            select(db_models.UsageBudgetPolicy)
            .where(
                db_models.UsageBudgetPolicy.id == policy_id,
                db_models.UsageBudgetPolicy.tenant_id == tenant_id,
            )
            .with_for_update()
        )
        if current is None:
            raise ValueError("budget policy not found")
        mutable = {
            "scope_kind",
            "window_kind",
            "target_group_id",
            "target_user_id",
            "llm_config_id",
            "stage",
            "cap_input_tokens",
            "cap_output_tokens",
            "cap_total_tokens",
            "cap_uncached_input_tokens",
            "cap_billable_tokens",
            "cap_usd",
            "cap_provider_requests",
            "soft_threshold_low",
            "soft_threshold_high",
            "unknown_price_action",
            "enabled",
            "effective_from",
            "effective_to",
        }
        unknown = set(changes) - mutable
        if unknown:
            raise ValueError(f"unsupported policy changes: {sorted(unknown)}")
        values = {name: getattr(current, name) for name in mutable}
        values.update(changes)
        values.update(
            tenant_id=tenant_id,
            reason=reason,
            created_by_user_id=created_by_user_id,
            logical_policy_id=current.logical_policy_id,
            version=current.version + 1,
            commit=commit,
        )
        return await self.create_policy(**values)

    async def disable_policy(
        self,
        *,
        policy_id: uuid.UUID,
        tenant_id: uuid.UUID,
        created_by_user_id: int,
        reason: str,
        commit: bool = True,
    ) -> db_models.UsageBudgetPolicy:
        return await self.replace_policy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            created_by_user_id=created_by_user_id,
            reason=reason,
            enabled=False,
            commit=commit,
        )

    async def _validate_policy_values(self, **values: Any) -> None:
        scope = values["scope_kind"]
        group_id = values["target_group_id"]
        user_id = values["target_user_id"]
        tenant_id = values["tenant_id"]
        if (
            (scope == "tenant" and (group_id is not None or user_id is not None))
            or (scope == "group" and (group_id is None or user_id is not None))
            or (scope == "user" and (user_id is None or group_id is not None))
        ):
            raise ValueError("budget policy scope target is inconsistent")
        if scope == "group":
            found = await self.db.scalar(
                select(db_models.UserGroup.id).where(
                    db_models.UserGroup.id == group_id,
                    db_models.UserGroup.tenant_id == tenant_id,
                )
            )
            if found is None:
                raise ValueError("budget group target is outside the tenant")
        if scope == "user":
            found = await self.db.scalar(
                select(db_models.User.id).where(
                    db_models.User.id == user_id,
                    db_models.User.tenant_id == tenant_id,
                )
            )
            if found is None:
                raise ValueError("budget user target is outside the tenant")
        caps = [values[f"cap_{name}"] for name in DIMENSIONS]
        if not any(value is not None for value in caps):
            raise ValueError("budget policy requires at least one cap")
        if any(value is not None and value < 0 for value in caps):
            raise ValueError("budget policy caps must be non-negative")
        if values["unknown_price_action"] == "token_only":
            token_caps = caps[:5]
            if not any(value is not None for value in token_caps):
                raise ValueError(
                    "token-only unknown pricing requires a finite token cap"
                )

    async def reserve(
        self, request: BudgetReservationRequest, *, commit: bool = True
    ) -> BudgetReservationDecision:
        existing = await self.db.scalar(
            select(db_models.UsageBudgetReservation).where(
                db_models.UsageBudgetReservation.idempotency_key
                == request.idempotency_key
            )
        )
        if existing is not None:
            if existing.tenant_id != request.tenant_id:
                raise ValueError("budget reservation idempotency key tenant mismatch")
            return BudgetReservationDecision(
                allowed=existing.state in {"held", "settled", "accounting_unknown"},
                reservation=existing,
                replayed=True,
            )

        now = request.at or datetime.now(timezone.utc)
        policies = await self.list_active_policies(
            tenant_id=request.tenant_id,
            user_id=request.actor_user_id,
            group_ids=request.group_ids,
            llm_config_id=request.llm_config_id,
            stage=request.stage,
            window_kinds=request.window_kinds,
            at=now,
        )
        if not policies:
            return BudgetReservationDecision(allowed=True)

        windows: dict[uuid.UUID, tuple[str, datetime, datetime]] = {}
        for policy in policies:
            windows[policy.id] = utc_window(
                policy.window_kind,
                at=now,
                request_key=request.request_key,
                scan_attempt_id=request.scan_attempt_id,
                expires_at=request.expires_at,
            )
            key, start, end = windows[policy.id]
            await self.db.execute(
                pg_insert(db_models.UsageBudgetCounter)
                .values(
                    id=uuid.uuid4(),
                    tenant_id=request.tenant_id,
                    policy_id=policy.id,
                    window_key=key,
                    window_start=start,
                    window_end=end,
                )
                .on_conflict_do_nothing(index_elements=["policy_id", "window_key"])
            )
        counters = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetCounter)
                    .where(
                        sa.or_(
                            *[
                                sa.and_(
                                    db_models.UsageBudgetCounter.policy_id == policy.id,
                                    db_models.UsageBudgetCounter.window_key
                                    == windows[policy.id][0],
                                )
                                for policy in policies
                            ]
                        )
                    )
                    .order_by(db_models.UsageBudgetCounter.policy_id)
                    .with_for_update()
                )
            ).all()
        )
        existing = await self.db.scalar(
            select(db_models.UsageBudgetReservation).where(
                db_models.UsageBudgetReservation.idempotency_key
                == request.idempotency_key
            )
        )
        if existing is not None:
            if commit:
                await self.db.commit()
            return BudgetReservationDecision(
                allowed=existing.state in {"held", "settled", "accounting_unknown"},
                reservation=existing,
                replayed=True,
            )
        counter_by_policy = {counter.policy_id: counter for counter in counters}
        parent_allocations: dict[uuid.UUID, db_models.UsageBudgetAllocation] = {}
        parent_remaining: dict[uuid.UUID, BudgetAmounts] = {}
        if request.parent_reservation_id is not None:
            parent = await self.db.scalar(
                select(db_models.UsageBudgetReservation)
                .where(
                    db_models.UsageBudgetReservation.id
                    == request.parent_reservation_id,
                    db_models.UsageBudgetReservation.tenant_id == request.tenant_id,
                    db_models.UsageBudgetReservation.state == "held",
                )
                .with_for_update()
            )
            if parent is None:
                raise ValueError("active parent budget reservation not found")
            if parent.scan_attempt_id != request.scan_attempt_id:
                raise ValueError("parent budget reservation belongs to another attempt")
            parent_rows = list(
                (
                    await self.db.scalars(
                        select(db_models.UsageBudgetAllocation).where(
                            db_models.UsageBudgetAllocation.reservation_id == parent.id
                        )
                    )
                ).all()
            )
            parent_allocations = {row.counter_id: row for row in parent_rows}
            parent_remaining = await self._parent_remaining(parent, parent_rows)

        increments: dict[uuid.UUID, BudgetAmounts] = {}
        for policy in policies:
            counter = counter_by_policy[policy.id]
            overrides = await self._active_override_allowance(
                policy.id, counter.window_key, now
            )
            parent_allocation = parent_allocations.get(counter.id)
            remaining_parent = parent_remaining.get(counter.id)
            increment_values: dict[str, int | Decimal] = {}
            for dimension in DIMENSIONS:
                requested = getattr(request.estimate, dimension)
                increment = requested
                if (
                    policy.window_kind != "request"
                    and parent_allocation is not None
                    and remaining_parent is not None
                ):
                    increment = max(requested - getattr(remaining_parent, dimension), 0)
                increment_values[dimension] = increment
                cap = getattr(policy, f"cap_{dimension}")
                if cap is None:
                    continue
                available = (
                    cap
                    + getattr(overrides, dimension)
                    - getattr(counter, f"spent_{dimension}")
                    - getattr(counter, f"held_{dimension}")
                )
                if increment > available:
                    await self.record_denial(
                        tenant_id=request.tenant_id,
                        actor_user_id=request.actor_user_id,
                        operation_kind=request.operation_kind,
                        request_key=request.request_key,
                        policy_id=policy.id,
                        reason_code="budget_hard_limit_exceeded",
                        commit=commit,
                    )
                    return BudgetReservationDecision(
                        allowed=False,
                        denial=BudgetDenial(
                            policy_id=policy.id,
                            scope_kind=policy.scope_kind,
                            window_kind=policy.window_kind,
                            dimension=dimension,
                            remaining=max(available, 0),
                            requested=increment,
                            reset_at=(
                                counter.window_end
                                if policy.window_kind in {"day", "month"}
                                else None
                            ),
                        ),
                    )
            increments[counter.id] = BudgetAmounts(**increment_values)

        reservation = db_models.UsageBudgetReservation(
            tenant_id=request.tenant_id,
            idempotency_key=request.idempotency_key,
            operation_kind=request.operation_kind,
            actor_user_id=request.actor_user_id,
            group_ids=list(request.group_ids),
            request_key=request.request_key,
            scan_attempt_id=request.scan_attempt_id,
            llm_config_id=request.llm_config_id,
            stage=request.stage,
            parent_reservation_id=request.parent_reservation_id,
            expires_at=request.expires_at,
            **request.estimate.as_model_values("estimated"),
        )
        self.db.add(reservation)
        await self.db.flush()
        for counter in counters:
            policy = next(row for row in policies if row.id == counter.policy_id)
            increment = increments[counter.id]
            for dimension in DIMENSIONS:
                setattr(
                    counter,
                    f"held_{dimension}",
                    getattr(counter, f"held_{dimension}")
                    + getattr(increment, dimension),
                )
            if (
                request.parent_reservation_id is not None
                and policy.window_kind != "request"
                and counter.id in parent_allocations
            ):
                parent_allocation = parent_allocations[counter.id]
                for dimension in DIMENSIONS:
                    setattr(
                        parent_allocation,
                        f"held_{dimension}",
                        getattr(parent_allocation, f"held_{dimension}")
                        + getattr(increment, dimension),
                    )
            self.db.add(
                db_models.UsageBudgetAllocation(
                    tenant_id=request.tenant_id,
                    reservation_id=reservation.id,
                    counter_id=counter.id,
                    **request.estimate.as_model_values("held"),
                )
            )
        await self.db.flush()
        await self.record_threshold_events(
            [counter.id for counter in counters], at=now, commit=False
        )
        if commit:
            await self.db.commit()
            await self.db.refresh(reservation)
        return BudgetReservationDecision(allowed=True, reservation=reservation)

    async def _parent_remaining(
        self,
        parent: db_models.UsageBudgetReservation,
        parent_allocations: Sequence[db_models.UsageBudgetAllocation],
    ) -> dict[uuid.UUID, BudgetAmounts]:
        children = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetReservation).where(
                        db_models.UsageBudgetReservation.parent_reservation_id
                        == parent.id,
                        db_models.UsageBudgetReservation.state.in_(
                            ("held", "settled", "accounting_unknown")
                        ),
                    )
                )
            ).all()
        )
        child_ids = [row.id for row in children]
        child_allocations = (
            list(
                (
                    await self.db.scalars(
                        select(db_models.UsageBudgetAllocation).where(
                            db_models.UsageBudgetAllocation.reservation_id.in_(
                                child_ids
                            )
                        )
                    )
                ).all()
            )
            if child_ids
            else []
        )
        settlements = (
            list(
                (
                    await self.db.scalars(
                        select(db_models.UsageBudgetSettlement).where(
                            db_models.UsageBudgetSettlement.reservation_id.in_(
                                child_ids
                            )
                        )
                    )
                ).all()
            )
            if child_ids
            else []
        )
        child_by_id = {row.id: row for row in children}
        settlement_by_reservation = {row.reservation_id: row for row in settlements}
        consumed: dict[uuid.UUID, dict[str, int | Decimal]] = {}
        for allocation in child_allocations:
            child = child_by_id[allocation.reservation_id]
            settlement = settlement_by_reservation.get(child.id)
            totals = consumed.setdefault(
                allocation.counter_id,
                {name: Decimal("0") if name == "usd" else 0 for name in DIMENSIONS},
            )
            for dimension in DIMENSIONS:
                if settlement is not None:
                    value = getattr(settlement, f"actual_{dimension}")
                else:
                    value = getattr(allocation, f"held_{dimension}")
                totals[dimension] += value
        result: dict[uuid.UUID, BudgetAmounts] = {}
        for allocation in parent_allocations:
            used = consumed.get(allocation.counter_id, {})
            result[allocation.counter_id] = BudgetAmounts(
                **{
                    name: max(
                        getattr(allocation, f"held_{name}") - used.get(name, 0),
                        0,
                    )
                    for name in DIMENSIONS
                }
            )
        return result

    async def _active_override_allowance(
        self, policy_id: uuid.UUID, window_key: str, at: datetime
    ) -> BudgetAmounts:
        columns = [
            sa.func.coalesce(
                sa.func.sum(
                    getattr(db_models.UsageBudgetOverride, f"allowance_{name}")
                ),
                0,
            ).label(name)
            for name in DIMENSIONS
        ]
        row = (
            await self.db.execute(
                select(*columns).where(
                    db_models.UsageBudgetOverride.policy_id == policy_id,
                    db_models.UsageBudgetOverride.window_key == window_key,
                    db_models.UsageBudgetOverride.effective_from <= at,
                    db_models.UsageBudgetOverride.expires_at > at,
                )
            )
        ).one()
        return BudgetAmounts(**{name: getattr(row, name) for name in DIMENSIONS})

    async def amounts_for_usage_event(
        self, usage_event_id: uuid.UUID, *, tenant_id: uuid.UUID | None = None
    ) -> BudgetAmounts:
        query = select(db_models.LLMUsageEvent).where(
            db_models.LLMUsageEvent.id == usage_event_id
        )
        if tenant_id is not None:
            query = query.where(db_models.LLMUsageEvent.tenant_id == tenant_id)
        event = await self.db.scalar(query)
        if event is None:
            raise ValueError("canonical usage event not found")
        uncached = max(event.input_tokens - event.cache_read_tokens, 0)
        return BudgetAmounts(
            input_tokens=event.input_tokens,
            output_tokens=event.output_tokens,
            total_tokens=event.total_tokens,
            uncached_input_tokens=uncached,
            billable_tokens=uncached + event.output_tokens,
            usd=event.total_cost or Decimal("0"),
            provider_requests=event.request_count,
        )

    async def settle(
        self,
        reservation_id: uuid.UUID,
        usage_event_id: uuid.UUID,
        actual: BudgetAmounts | None = None,
        *,
        commit: bool = True,
    ) -> db_models.UsageBudgetSettlement:
        replay = await self.db.scalar(
            select(db_models.UsageBudgetSettlement).where(
                db_models.UsageBudgetSettlement.usage_event_id == usage_event_id
            )
        )
        if replay is not None:
            if replay.reservation_id != reservation_id:
                raise ValueError("usage event is settled to another reservation")
            return replay
        reservation = await self.db.scalar(
            select(db_models.UsageBudgetReservation)
            .where(db_models.UsageBudgetReservation.id == reservation_id)
            .with_for_update()
        )
        if reservation is None:
            raise ValueError("budget reservation not found")
        if reservation.state != "held":
            replay = await self.db.scalar(
                select(db_models.UsageBudgetSettlement).where(
                    db_models.UsageBudgetSettlement.usage_event_id == usage_event_id,
                    db_models.UsageBudgetSettlement.reservation_id == reservation_id,
                )
            )
            if replay is not None:
                return replay
            raise ValueError(f"cannot settle reservation in state {reservation.state}")
        event = await self.db.scalar(
            select(db_models.LLMUsageEvent).where(
                db_models.LLMUsageEvent.id == usage_event_id,
                db_models.LLMUsageEvent.tenant_id == reservation.tenant_id,
            )
        )
        if event is None:
            raise ValueError("canonical usage event not found in reservation tenant")
        if actual is None:
            actual = await self.amounts_for_usage_event(
                usage_event_id, tenant_id=reservation.tenant_id
            )
            if event.total_cost is None:
                actual = BudgetAmounts(
                    **{
                        **{name: getattr(actual, name) for name in DIMENSIONS},
                        "usd": reservation.estimated_usd,
                    }
                )
        allocations = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetAllocation).where(
                        db_models.UsageBudgetAllocation.reservation_id == reservation_id
                    )
                )
            ).all()
        )
        counter_ids = sorted((row.counter_id for row in allocations), key=str)
        counters = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetCounter)
                    .where(db_models.UsageBudgetCounter.id.in_(counter_ids))
                    .order_by(db_models.UsageBudgetCounter.policy_id)
                    .with_for_update()
                )
            ).all()
        )
        allocation_by_counter = {row.counter_id: row for row in allocations}
        parent_counter_ids: set[uuid.UUID] = set()
        if reservation.parent_reservation_id is not None:
            parent_counter_ids = set(
                (
                    await self.db.scalars(
                        select(db_models.UsageBudgetAllocation.counter_id).where(
                            db_models.UsageBudgetAllocation.reservation_id
                            == reservation.parent_reservation_id
                        )
                    )
                ).all()
            )
        policy_windows = dict(
            (
                await self.db.execute(
                    select(
                        db_models.UsageBudgetPolicy.id,
                        db_models.UsageBudgetPolicy.window_kind,
                    ).where(
                        db_models.UsageBudgetPolicy.id.in_(
                            [counter.policy_id for counter in counters]
                        )
                    )
                )
            ).all()
        )
        overruns: dict[str, str] = {}
        for counter in counters:
            allocation = allocation_by_counter[counter.id]
            draws_parent = (
                counter.id in parent_counter_ids
                and policy_windows[counter.policy_id] != "request"
            )
            for dimension in DIMENSIONS:
                held = getattr(allocation, f"held_{dimension}")
                value = getattr(actual, dimension)
                held_to_release = value if draws_parent else held
                setattr(
                    counter,
                    f"held_{dimension}",
                    max(
                        getattr(counter, f"held_{dimension}") - held_to_release,
                        0,
                    ),
                )
                setattr(
                    counter,
                    f"spent_{dimension}",
                    getattr(counter, f"spent_{dimension}") + value,
                )
                if value > held:
                    overruns[dimension] = str(value - held)
            counter.updated_at = datetime.now(timezone.utc)
        settlement = db_models.UsageBudgetSettlement(
            tenant_id=reservation.tenant_id,
            reservation_id=reservation.id,
            usage_event_id=usage_event_id,
            overrun=overruns,
            **actual.as_model_values("actual"),
        )
        reservation.state = "settled"
        reservation.finalized_at = datetime.now(timezone.utc)
        self.db.add(settlement)
        await self.db.flush()
        await self.record_threshold_events(
            [counter.id for counter in counters], commit=False
        )
        if commit:
            await self.db.commit()
            await self.db.refresh(settlement)
        return settlement

    async def release(
        self, reservation_id: uuid.UUID, reason: str, *, commit: bool = True
    ) -> bool:
        reservation = await self.db.scalar(
            select(db_models.UsageBudgetReservation)
            .where(db_models.UsageBudgetReservation.id == reservation_id)
            .with_for_update()
        )
        if reservation is None:
            return False
        if reservation.state in {"released", "expired"}:
            return True
        if reservation.state != "held":
            return False
        await self._release_allocations(reservation)
        reservation.state = "released"
        reservation.release_reason = reason[:100]
        reservation.finalized_at = datetime.now(timezone.utc)
        if commit:
            await self.db.commit()
        return True

    async def mark_accounting_unknown(
        self, reservation_id: uuid.UUID, reason: str, *, commit: bool = True
    ) -> bool:
        reservation = await self.db.scalar(
            select(db_models.UsageBudgetReservation)
            .where(db_models.UsageBudgetReservation.id == reservation_id)
            .with_for_update()
        )
        if reservation is None:
            return False
        if reservation.state == "accounting_unknown":
            return True
        if reservation.state != "held":
            return False
        allocations = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetAllocation).where(
                        db_models.UsageBudgetAllocation.reservation_id == reservation.id
                    )
                )
            ).all()
        )
        counter_ids = [allocation.counter_id for allocation in allocations]
        counters = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetCounter)
                    .where(db_models.UsageBudgetCounter.id.in_(counter_ids))
                    .order_by(db_models.UsageBudgetCounter.policy_id)
                    .with_for_update()
                )
            ).all()
        )
        by_counter = {allocation.counter_id: allocation for allocation in allocations}
        for counter in counters:
            allocation = by_counter[counter.id]
            for dimension in DIMENSIONS:
                held = getattr(allocation, f"held_{dimension}")
                setattr(
                    counter,
                    f"held_{dimension}",
                    getattr(counter, f"held_{dimension}") - held,
                )
                setattr(
                    counter,
                    f"spent_{dimension}",
                    getattr(counter, f"spent_{dimension}") + held,
                )
        reservation.state = "accounting_unknown"
        reservation.release_reason = reason[:100]
        reservation.finalized_at = datetime.now(timezone.utc)
        await self.record_threshold_events(
            [counter.id for counter in counters], commit=False
        )
        if commit:
            await self.db.commit()
        return True

    async def _release_allocations(
        self, reservation: db_models.UsageBudgetReservation
    ) -> None:
        allocations = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetAllocation).where(
                        db_models.UsageBudgetAllocation.reservation_id == reservation.id
                    )
                )
            ).all()
        )
        ids = [row.counter_id for row in allocations]
        counters = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetCounter)
                    .where(db_models.UsageBudgetCounter.id.in_(ids))
                    .order_by(db_models.UsageBudgetCounter.policy_id)
                    .with_for_update()
                )
            ).all()
        )
        allocation_by_counter = {row.counter_id: row for row in allocations}
        parent_counter_ids: set[uuid.UUID] = set()
        if reservation.parent_reservation_id is not None:
            parent_counter_ids = set(
                (
                    await self.db.scalars(
                        select(db_models.UsageBudgetAllocation.counter_id).where(
                            db_models.UsageBudgetAllocation.reservation_id
                            == reservation.parent_reservation_id
                        )
                    )
                ).all()
            )
        policy_windows = dict(
            (
                await self.db.execute(
                    select(
                        db_models.UsageBudgetPolicy.id,
                        db_models.UsageBudgetPolicy.window_kind,
                    ).where(
                        db_models.UsageBudgetPolicy.id.in_(
                            [counter.policy_id for counter in counters]
                        )
                    )
                )
            ).all()
        )
        parent_remaining = await self._parent_remaining(reservation, allocations)
        has_children = (
            await self.db.scalar(
                select(sa.func.count())
                .select_from(db_models.UsageBudgetReservation)
                .where(
                    db_models.UsageBudgetReservation.parent_reservation_id
                    == reservation.id
                )
            )
        ) > 0
        for counter in counters:
            allocation = allocation_by_counter[counter.id]
            if (
                counter.id in parent_counter_ids
                and policy_windows[counter.policy_id] != "request"
            ):
                continue
            for dimension in DIMENSIONS:
                current = getattr(counter, f"held_{dimension}")
                release_amount = getattr(allocation, f"held_{dimension}")
                if has_children:
                    release_amount = getattr(parent_remaining[counter.id], dimension)
                setattr(
                    counter,
                    f"held_{dimension}",
                    max(current - release_amount, 0),
                )
            counter.updated_at = datetime.now(timezone.utc)

    async def release_expired(self, *, at: datetime | None = None) -> int:
        now = at or datetime.now(timezone.utc)
        rows = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetReservation)
                    .outerjoin(
                        db_models.LLMUsageEvent,
                        db_models.LLMUsageEvent.idempotency_key
                        == db_models.UsageBudgetReservation.request_key,
                    )
                    .where(
                        db_models.UsageBudgetReservation.state == "held",
                        db_models.UsageBudgetReservation.expires_at <= now,
                        db_models.LLMUsageEvent.id.is_(None),
                    )
                    .order_by(db_models.UsageBudgetReservation.id)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for reservation in rows:
            await self._release_allocations(reservation)
            reservation.state = "expired"
            reservation.release_reason = "orphan_hold_expired"
            reservation.finalized_at = now
        await self.db.commit()
        return len(rows)

    async def find_active_scan_parent(
        self, scan_attempt_id: uuid.UUID, stage: str | None = None
    ) -> db_models.UsageBudgetReservation | None:
        query = select(db_models.UsageBudgetReservation).where(
            db_models.UsageBudgetReservation.scan_attempt_id == scan_attempt_id,
            db_models.UsageBudgetReservation.parent_reservation_id.is_(None),
            db_models.UsageBudgetReservation.state == "held",
            db_models.UsageBudgetReservation.request_key.like("scan-gate:%"),
        )
        if stage is not None:
            query = query.where(db_models.UsageBudgetReservation.stage == stage)
        return await self.db.scalar(
            query.order_by(db_models.UsageBudgetReservation.created_at.desc()).limit(1)
        )

    async def release_scan_attempt(
        self,
        *,
        scan_id: uuid.UUID,
        reason: str,
        commit: bool = True,
    ) -> int:
        attempt_id = await self.db.scalar(
            select(db_models.Scan.current_attempt_id).where(
                db_models.Scan.id == scan_id
            )
        )
        if attempt_id is None:
            return 0
        reservations = list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetReservation)
                    .where(
                        db_models.UsageBudgetReservation.scan_attempt_id == attempt_id,
                        db_models.UsageBudgetReservation.state == "held",
                    )
                    .order_by(
                        db_models.UsageBudgetReservation.parent_reservation_id.desc().nulls_last(),
                        db_models.UsageBudgetReservation.created_at.desc(),
                    )
                    .with_for_update()
                )
            ).all()
        )
        released = 0
        for reservation in reservations:
            if await self.release(reservation.id, reason, commit=False):
                released += 1
        if commit:
            await self.db.commit()
        return released

    async def create_override(
        self,
        *,
        tenant_id: uuid.UUID,
        policy_id: uuid.UUID,
        window_key: str,
        allowance: BudgetAmounts,
        reason: str,
        created_by_user_id: int,
        effective_from: datetime,
        expires_at: datetime,
        commit: bool = True,
    ) -> db_models.UsageBudgetOverride:
        policy = await self.get_policy(policy_id, tenant_id)
        if policy is None:
            raise ValueError("budget policy not found")
        counter = await self.db.scalar(
            select(db_models.UsageBudgetCounter).where(
                db_models.UsageBudgetCounter.policy_id == policy_id,
                db_models.UsageBudgetCounter.window_key == window_key,
                db_models.UsageBudgetCounter.tenant_id == tenant_id,
            )
        )
        if counter is None:
            raise ValueError("budget override window has no policy counter")
        if expires_at > effective_from + timedelta(hours=24):
            raise ValueError("budget override cannot exceed 24 hours")
        if expires_at > counter.window_end:
            raise ValueError("budget override cannot outlive its policy window")
        if len(reason.strip()) < 10:
            raise ValueError("budget override reason must be at least 10 characters")
        row = db_models.UsageBudgetOverride(
            tenant_id=tenant_id,
            policy_id=policy_id,
            window_key=window_key,
            reason=reason.strip(),
            created_by_user_id=created_by_user_id,
            effective_from=effective_from,
            expires_at=expires_at,
            **allowance.as_model_values("allowance"),
        )
        self.db.add(row)
        await self.db.flush()
        if commit:
            await self.db.commit()
            await self.db.refresh(row)
        return row

    async def record_threshold_events(
        self,
        counter_ids: Sequence[uuid.UUID],
        *,
        at: datetime | None = None,
        commit: bool = True,
    ) -> list[db_models.UsageBudgetThresholdEvent]:
        if not counter_ids:
            return []
        now = at or datetime.now(timezone.utc)
        rows = (
            await self.db.execute(
                select(db_models.UsageBudgetCounter, db_models.UsageBudgetPolicy)
                .join(
                    db_models.UsageBudgetPolicy,
                    db_models.UsageBudgetPolicy.id
                    == db_models.UsageBudgetCounter.policy_id,
                )
                .where(db_models.UsageBudgetCounter.id.in_(tuple(counter_ids)))
            )
        ).all()
        created_ids: list[uuid.UUID] = []
        for counter, policy in rows:
            allowance = await self._active_override_allowance(
                policy.id, counter.window_key, now
            )
            for dimension in DIMENSIONS:
                cap = getattr(policy, f"cap_{dimension}")
                if cap is None:
                    continue
                effective_cap = cap + getattr(allowance, dimension)
                if effective_cap <= 0:
                    continue
                observed = getattr(counter, f"spent_{dimension}") + getattr(
                    counter, f"held_{dimension}"
                )
                for threshold in (
                    policy.soft_threshold_low,
                    policy.soft_threshold_high,
                ):
                    if Decimal(observed) * 100 < Decimal(effective_cap) * threshold:
                        continue
                    event_id = uuid.uuid4()
                    inserted = await self.db.scalar(
                        pg_insert(db_models.UsageBudgetThresholdEvent)
                        .values(
                            id=event_id,
                            tenant_id=counter.tenant_id,
                            policy_id=policy.id,
                            counter_id=counter.id,
                            dimension=dimension,
                            threshold_percent=threshold,
                            observed=observed,
                            effective_cap=effective_cap,
                        )
                        .on_conflict_do_nothing(
                            index_elements=[
                                "counter_id",
                                "dimension",
                                "threshold_percent",
                            ]
                        )
                        .returning(db_models.UsageBudgetThresholdEvent.id)
                    )
                    if inserted is not None:
                        created_ids.append(inserted)
                        recipients = set(
                            (
                                await self.db.scalars(
                                    select(db_models.RoleAssignment.user_id).where(
                                        db_models.RoleAssignment.tenant_id
                                        == counter.tenant_id,
                                        db_models.RoleAssignment.role_key.in_(
                                            ("tenant_admin", "security_approver")
                                        ),
                                    )
                                )
                            ).all()
                        )
                        if policy.scope_kind == "user" and policy.target_user_id:
                            recipients.add(policy.target_user_id)
                        for recipient_user_id in sorted(recipients):
                            await self.db.execute(
                                pg_insert(db_models.UsageBudgetNotificationOutbox)
                                .values(
                                    id=uuid.uuid4(),
                                    tenant_id=counter.tenant_id,
                                    threshold_event_id=inserted,
                                    recipient_user_id=recipient_user_id,
                                    state="pending",
                                )
                                .on_conflict_do_nothing(
                                    index_elements=[
                                        "threshold_event_id",
                                        "recipient_user_id",
                                    ]
                                )
                            )
        if commit:
            await self.db.commit()
        if not created_ids:
            return []
        return list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetThresholdEvent).where(
                        db_models.UsageBudgetThresholdEvent.id.in_(created_ids)
                    )
                )
            ).all()
        )

    async def list_threshold_events(
        self,
        tenant_id: uuid.UUID,
        *,
        policy_id: uuid.UUID | None = None,
        limit: int = 100,
    ) -> list[db_models.UsageBudgetThresholdEvent]:
        query = select(db_models.UsageBudgetThresholdEvent).where(
            db_models.UsageBudgetThresholdEvent.tenant_id == tenant_id
        )
        if policy_id is not None:
            query = query.where(
                db_models.UsageBudgetThresholdEvent.policy_id == policy_id
            )
        return list(
            (
                await self.db.scalars(
                    query.order_by(
                        db_models.UsageBudgetThresholdEvent.created_at.desc()
                    ).limit(max(1, min(limit, 1000)))
                )
            ).all()
        )

    async def list_pending_notifications(
        self, tenant_id: uuid.UUID, *, limit: int = 100
    ) -> list[db_models.UsageBudgetNotificationOutbox]:
        return list(
            (
                await self.db.scalars(
                    select(db_models.UsageBudgetNotificationOutbox)
                    .where(
                        db_models.UsageBudgetNotificationOutbox.tenant_id == tenant_id,
                        db_models.UsageBudgetNotificationOutbox.state == "pending",
                    )
                    .order_by(db_models.UsageBudgetNotificationOutbox.created_at)
                    .limit(max(1, min(limit, 1000)))
                )
            ).all()
        )

    async def list_counters(
        self,
        tenant_id: uuid.UUID,
        *,
        policy_id: uuid.UUID | None = None,
        limit: int = 100,
    ) -> list[db_models.UsageBudgetCounter]:
        query = select(db_models.UsageBudgetCounter).where(
            db_models.UsageBudgetCounter.tenant_id == tenant_id
        )
        if policy_id is not None:
            query = query.where(db_models.UsageBudgetCounter.policy_id == policy_id)
        return list(
            (
                await self.db.scalars(
                    query.order_by(
                        db_models.UsageBudgetCounter.window_start.desc()
                    ).limit(max(1, min(limit, 1000)))
                )
            ).all()
        )

    async def list_reservations(
        self,
        tenant_id: uuid.UUID,
        *,
        state: str | None = None,
        limit: int = 100,
    ) -> list[db_models.UsageBudgetReservation]:
        query = select(db_models.UsageBudgetReservation).where(
            db_models.UsageBudgetReservation.tenant_id == tenant_id
        )
        if state is not None:
            query = query.where(db_models.UsageBudgetReservation.state == state)
        return list(
            (
                await self.db.scalars(
                    query.order_by(
                        db_models.UsageBudgetReservation.created_at.desc()
                    ).limit(max(1, min(limit, 1000)))
                )
            ).all()
        )

    async def list_overrides(
        self,
        tenant_id: uuid.UUID,
        *,
        policy_id: uuid.UUID | None = None,
        active_only: bool = False,
        at: datetime | None = None,
    ) -> list[db_models.UsageBudgetOverride]:
        query = select(db_models.UsageBudgetOverride).where(
            db_models.UsageBudgetOverride.tenant_id == tenant_id
        )
        if policy_id is not None:
            query = query.where(db_models.UsageBudgetOverride.policy_id == policy_id)
        if active_only:
            now = at or datetime.now(timezone.utc)
            query = query.where(
                db_models.UsageBudgetOverride.effective_from <= now,
                db_models.UsageBudgetOverride.expires_at > now,
            )
        return list(
            (
                await self.db.scalars(
                    query.order_by(db_models.UsageBudgetOverride.created_at.desc())
                )
            ).all()
        )
