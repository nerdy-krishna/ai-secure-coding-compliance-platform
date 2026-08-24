"""Deliver leased outbox rows without exposing connector secrets or raw payloads."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.integration_repo import IntegrationRepository
from app.infrastructure.integrations.clients import (
    DeliveryResult,
    JiraCloudClient,
    PinnedHttpClient,
    SiemWebhookClient,
)
from app.infrastructure.integrations.secrets import decrypt_principal_secrets
from app.shared.lib.integration_contract import build_envelope, stable_idempotency_key


class IntegrationDeliveryDispatcher:
    def __init__(
        self,
        *,
        repo: IntegrationRepository,
        http: PinnedHttpClient,
    ) -> None:
        self.repo = repo
        self.http = http

    async def deliver(self, row: db_models.IntegrationOutbox) -> DeliveryResult:
        principal = await self.repo.get_principal(
            tenant_id=row.tenant_id,
            principal_id=row.principal_id,
            active_only=True,
        )
        if principal is None:
            return DeliveryResult(False, False, None, "principal_revoked")
        if principal.kind == "siem_webhook":
            return await self._deliver_siem(row, principal)
        if principal.kind == "jira_cloud":
            return await self._deliver_jira(row, principal)
        return DeliveryResult(False, False, None, "unsupported_outbox_delivery_kind")

    async def _deliver_siem(
        self,
        row: db_models.IntegrationOutbox,
        principal: db_models.IntegrationServicePrincipal,
    ) -> DeliveryResult:
        if not await self.repo.has_active_grant(
            tenant_id=row.tenant_id,
            principal_id=row.principal_id,
            feature="siem_emit",
            event_type=row.event_type,
            lock=True,
        ):
            return DeliveryResult(False, False, None, "grant_revoked")
        secrets = await decrypt_principal_secrets(principal)
        sent_at = datetime.now(timezone.utc)
        envelope = build_envelope(
            event_id=str(row.id),
            event_type=row.event_type,
            tenant_id=str(row.tenant_id),
            nonce=stable_idempotency_key(row.nonce, row.attempts),
            timestamp=int(sent_at.timestamp()),
            idempotency_key=row.idempotency_key,
            payload=row.payload_redacted,
            occurred_at=row.occurred_at,
            delivery_attempt=row.attempts,
        )
        client = SiemWebhookClient(
            endpoint=str(principal.config["endpoint"]),
            allowed_host=str(principal.config["allowed_host"]),
            signing_secret=secrets["signing_secret"],
            http=self.http,
        )
        return await client.deliver(envelope)

    async def _deliver_jira(
        self,
        row: db_models.IntegrationOutbox,
        principal: db_models.IntegrationServicePrincipal,
    ) -> DeliveryResult:
        if row.event_type != "finding.ticket.sync":
            return DeliveryResult(False, False, None, "unsupported_jira_event")
        if not await self.repo.has_active_grant(
            tenant_id=row.tenant_id,
            principal_id=row.principal_id,
            feature="ticket_sync",
            lock=True,
        ):
            return DeliveryResult(False, False, None, "grant_revoked")
        payload = row.payload_redacted
        root_id = str(payload.get("canonical_root_id") or "")
        if not root_id or len(root_id) > 128:
            return DeliveryResult(False, False, None, "canonical_root_invalid")
        desired_status = str(payload.get("status") or "")
        mapping = principal.config.get("status_mapping")
        entry: Any = mapping.get(desired_status) if isinstance(mapping, dict) else None
        if not isinstance(entry, dict) or not str(entry.get("transition_id") or ""):
            return DeliveryResult(False, False, None, "jira_status_mapping_missing")
        connector_secrets = await decrypt_principal_secrets(principal)
        client = JiraCloudClient(
            base_url=str(principal.config["base_url"]),
            allowed_host=str(principal.config["allowed_host"]),
            email=connector_secrets["email"],
            api_token=connector_secrets["api_token"],
            http=self.http,
        )
        label = f"sccap-root-{hashlib.sha256(root_id.encode('utf-8')).hexdigest()[:32]}"
        await self.repo.lock_ticket_identity(
            principal_id=row.principal_id,
            canonical_root_id=root_id,
        )
        ticket = await self.repo.get_ticket(
            tenant_id=row.tenant_id,
            principal_id=row.principal_id,
            canonical_root_id=root_id,
        )
        if ticket is None:
            found = await client.find_issue_by_label(label=label)
            if found is None:
                created, external_key = await client.create_issue(
                    project_key=str(principal.config["project_key"]),
                    issue_type=str(principal.config.get("issue_type") or "Task"),
                    summary=f"[{payload.get('severity', 'unknown')}] {payload.get('title', 'SCCAP finding')}",
                    description=(
                        f"Canonical SCCAP finding {root_id}. "
                        f"Authorized view: {payload.get('authorized_view', '')}"
                    ),
                    canonical_label=label,
                )
                if not created.delivered or not external_key:
                    return created
                observed_status = str(principal.config.get("initial_status") or "open")
            else:
                external_key, observed_status = found
            ticket = await self.repo.create_ticket(
                tenant_id=row.tenant_id,
                principal_id=row.principal_id,
                canonical_root_id=root_id,
                external_key=external_key,
                external_url=f"{str(principal.config['base_url']).rstrip('/')}/browse/{external_key}",
                status=observed_status,
                waiver_expires_at=_optional_datetime(payload.get("waiver_expires_at")),
                reason="recovered" if found is not None else "created",
            )
        if ticket.status == desired_status:
            if (
                str(payload.get("reason") or "") == "waiver_expired"
                and ticket.waiver_expires_at is not None
            ):
                await self.repo.transition_ticket(
                    row=ticket,
                    to_status=desired_status,
                    reason="waiver_expired",
                    event_id=row.id,
                    waiver_expires_at=None,
                )
            return DeliveryResult(True, False, 200, response_excerpt='{"status":"unchanged"}')
        transitioned = await client.transition_issue(
            issue_key=ticket.external_key,
            transition_id=str(entry["transition_id"]),
        )
        if transitioned.delivered:
            await self.repo.transition_ticket(
                row=ticket,
                to_status=desired_status,
                reason=str(payload.get("reason") or "finding_status_changed")[:96],
                event_id=row.id,
                waiver_expires_at=_optional_datetime(payload.get("waiver_expires_at")),
            )
        return transitioned


def _optional_datetime(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
