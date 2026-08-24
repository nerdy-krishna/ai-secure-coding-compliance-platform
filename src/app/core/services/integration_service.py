"""Enterprise integration orchestration over encrypted, tenant-owned principals."""

from __future__ import annotations

import json
import re
import secrets
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select

from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.integration_repo import IntegrationRepository
from app.infrastructure.integrations.clients import (
    DeliveryResult,
    GitHubAppClient,
    PinnedHttpClient,
    verify_github_webhook_signature,
)
from app.infrastructure.integrations.secrets import (
    decrypt_integration_secrets,
    encrypt_integration_secrets,
)
from app.shared.lib.integration_contract import (
    IntegrationContractError,
    payload_digest,
    redact_integration_payload,
    stable_idempotency_key,
    validate_https_endpoint,
)


PRINCIPAL_KINDS = frozenset({"github_app", "jira_cloud", "siem_webhook"})
FEATURES_BY_KIND = {
    "github_app": frozenset(
        {
            "repository_contents_read",
            "security_events_write",
            "webhook_metadata_read",
        }
    ),
    "jira_cloud": frozenset({"ticket_sync"}),
    "siem_webhook": frozenset({"siem_emit"}),
}
REQUIRED_SECRET_KEYS = {
    "github_app": frozenset({"private_key_pem", "webhook_secret"}),
    "jira_cloud": frozenset({"email", "api_token"}),
    "siem_webhook": frozenset({"signing_secret"}),
}

_GITHUB_CONFIG_KEYS = frozenset({"app_id", "installation_id", "owner", "repository"})
_JIRA_CONFIG_KEYS = frozenset(
    {
        "base_url",
        "allowed_host",
        "project_key",
        "issue_type",
        "initial_status",
        "waived_status",
        "reopen_status",
        "status_mapping",
    }
)
_SIEM_CONFIG_KEYS = frozenset({"endpoint", "allowed_host"})
_GITHUB_NAME_RE = re.compile(r"[-_.A-Za-z0-9]{1,100}\Z")
_JIRA_PROJECT_RE = re.compile(r"[A-Z][A-Z0-9_]{0,19}\Z")
_EVENT_TYPE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")


def _bounded_text(value: object, *, field: str, maximum: int) -> str:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise IntegrationContractError(f"{field} must be text")
    normalized = str(value).strip()
    if not normalized or len(normalized) > maximum or any(
        ord(character) < 32 for character in normalized
    ):
        raise IntegrationContractError(f"{field} is empty, malformed, or too long")
    return normalized


def _require_allowed_keys(
    config: Mapping[str, Any],
    allowed: frozenset[str],
    *,
    required: frozenset[str],
    kind: str,
) -> None:
    keys = set(config)
    if keys - allowed:
        raise IntegrationContractError(f"{kind} configuration contains an unknown field")
    if required - keys:
        raise IntegrationContractError(f"{kind} configuration is incomplete")


def _require_exact_keys(
    config: Mapping[str, Any], required: frozenset[str], *, kind: str
) -> None:
    _require_allowed_keys(config, required, required=required, kind=kind)


def _normalize_status_mapping(value: object) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping) or not 1 <= len(value) <= 32:
        raise IntegrationContractError("Jira status mapping must contain 1 to 32 entries")
    normalized: dict[str, dict[str, str]] = {}
    for raw_status, raw_entry in value.items():
        status = _bounded_text(raw_status, field="Jira status", maximum=64)
        if (
            not isinstance(raw_entry, Mapping)
            or set(raw_entry) != {"transition_id"}
        ):
            raise IntegrationContractError(
                "each Jira status mapping entry must contain only transition_id"
            )
        transition_id = _bounded_text(
            raw_entry["transition_id"], field="Jira transition_id", maximum=20
        )
        if not transition_id.isdigit():
            raise IntegrationContractError("Jira transition_id must be decimal")
        normalized[status] = {"transition_id": transition_id}
    return normalized


def _normalize_grant_scope(
    *,
    principal: db_models.IntegrationServicePrincipal,
    feature: str,
    scope: Mapping[str, Any],
) -> dict[str, Any]:
    if any(not isinstance(key, str) for key in scope):
        raise IntegrationContractError("integration grant scope keys must be strings")
    if principal.kind == "github_app":
        _require_exact_keys(scope, frozenset({"repository"}), kind="GitHub grant")
        repository = _bounded_text(
            scope["repository"], field="repository scope", maximum=201
        )
        expected = f"{principal.config['owner']}/{principal.config['repository']}"
        if repository.casefold() != expected.casefold():
            raise IntegrationContractError("GitHub grant scope does not match the connector")
        return {"repository": expected}
    if principal.kind == "jira_cloud":
        _require_exact_keys(scope, frozenset({"project_key"}), kind="Jira grant")
        project_key = _bounded_text(
            scope["project_key"], field="project_key scope", maximum=20
        )
        if project_key != principal.config["project_key"]:
            raise IntegrationContractError("Jira grant scope does not match the connector")
        return {"project_key": project_key}
    _require_exact_keys(scope, frozenset({"event_types"}), kind="SIEM grant")
    event_types = scope["event_types"]
    if (
        not isinstance(event_types, list)
        or not 1 <= len(event_types) <= 32
        or any(
            not isinstance(event_type, str)
            or not _EVENT_TYPE_RE.fullmatch(event_type)
            for event_type in event_types
        )
    ):
        raise IntegrationContractError(
            "SIEM event_types scope must contain 1 to 32 bounded event names"
        )
    return {"event_types": sorted(set(event_types))}


class IntegrationService:
    def __init__(self, repo: IntegrationRepository) -> None:
        self.repo = repo

    @staticmethod
    def validate_configuration(
        *, kind: str, config: Mapping[str, Any], secret_values: Mapping[str, str]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        if kind not in PRINCIPAL_KINDS:
            raise IntegrationContractError("unsupported integration kind")
        missing = REQUIRED_SECRET_KEYS[kind] - set(secret_values)
        if missing:
            raise IntegrationContractError(
                f"missing required integration secrets: {', '.join(sorted(missing))}"
            )
        if set(secret_values) != REQUIRED_SECRET_KEYS[kind]:
            raise IntegrationContractError("unexpected integration secret field")
        if any(
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 64 * 1024
            for value in secret_values.values()
        ):
            raise IntegrationContractError("integration secrets must be non-empty and bounded")
        if kind == "github_app" and not secret_values["private_key_pem"].startswith(
            "-----BEGIN"
        ):
            raise IntegrationContractError("GitHub App private key must be PEM encoded")
        if kind in {"github_app", "siem_webhook"}:
            signing_key = (
                secret_values["webhook_secret"]
                if kind == "github_app"
                else secret_values["signing_secret"]
            )
            if len(signing_key.encode("utf-8")) < 32:
                raise IntegrationContractError("webhook signing secret must contain 32 bytes")
        if any(not isinstance(key, str) for key in config):
            raise IntegrationContractError("integration configuration keys must be strings")
        if kind == "github_app":
            _require_exact_keys(config, _GITHUB_CONFIG_KEYS, kind="GitHub App")
            safe_config = {
                "app_id": _bounded_text(config["app_id"], field="app_id", maximum=20),
                "installation_id": _bounded_text(
                    config["installation_id"], field="installation_id", maximum=20
                ),
                "owner": _bounded_text(config["owner"], field="owner", maximum=100),
                "repository": _bounded_text(
                    config["repository"], field="repository", maximum=100
                ),
            }
            if not safe_config["app_id"].isdigit() or not safe_config[
                "installation_id"
            ].isdigit():
                raise IntegrationContractError("GitHub App identifiers must be decimal")
            if not _GITHUB_NAME_RE.fullmatch(safe_config["owner"]) or not _GITHUB_NAME_RE.fullmatch(
                safe_config["repository"]
            ):
                raise IntegrationContractError("invalid GitHub repository identity")
            safe_config["api_host"] = "api.github.com"
            selected_host = "api.github.com"
        elif kind == "jira_cloud":
            _require_allowed_keys(
                config,
                _JIRA_CONFIG_KEYS,
                required=frozenset(
                    {"base_url", "allowed_host", "project_key", "status_mapping"}
                ),
                kind="Jira Cloud",
            )
            safe_config = {
                "base_url": _bounded_text(
                    config["base_url"], field="base_url", maximum=512
                ),
                "allowed_host": _bounded_text(
                    config["allowed_host"], field="allowed_host", maximum=253
                ).casefold(),
                "project_key": _bounded_text(
                    config["project_key"], field="project_key", maximum=20
                ),
                "issue_type": _bounded_text(
                    config.get("issue_type", "Task"), field="issue_type", maximum=64
                ),
                "initial_status": _bounded_text(
                    config.get("initial_status", "open"),
                    field="initial_status",
                    maximum=64,
                ),
                "waived_status": _bounded_text(
                    config.get("waived_status", "waived"),
                    field="waived_status",
                    maximum=64,
                ),
                "reopen_status": _bounded_text(
                    config.get("reopen_status", "open"),
                    field="reopen_status",
                    maximum=64,
                ),
                "status_mapping": _normalize_status_mapping(config["status_mapping"]),
            }
            base_url = str(safe_config.get("base_url") or "")
            allowed_host = str(safe_config.get("allowed_host") or "").casefold()
            actual_host = (urlsplit(base_url).hostname or "").casefold()
            if actual_host != allowed_host or not allowed_host.endswith(".atlassian.net"):
                raise IntegrationContractError(
                    "Jira base URL must match the explicit atlassian.net allowlist host"
                )
            validate_https_endpoint(base_url, allowed_hosts=(allowed_host,))
            selected_host = allowed_host
            parsed_base = urlsplit(base_url)
            if parsed_base.path not in ("", "/") or parsed_base.query or parsed_base.fragment:
                raise IntegrationContractError("Jira base URL must not include a path or query")
            if not _JIRA_PROJECT_RE.fullmatch(safe_config["project_key"]):
                raise IntegrationContractError("invalid Jira project key")
            mapping = safe_config.get("status_mapping")
            if any(
                safe_config[key] not in mapping
                for key in ("waived_status", "reopen_status")
            ):
                raise IntegrationContractError(
                    "Jira status mapping must include waived and reopen statuses"
                )
        else:
            _require_exact_keys(config, _SIEM_CONFIG_KEYS, kind="SIEM webhook")
            safe_config = {
                "endpoint": _bounded_text(
                    config["endpoint"], field="endpoint", maximum=1024
                ),
                "allowed_host": _bounded_text(
                    config["allowed_host"], field="allowed_host", maximum=253
                ).casefold(),
            }
            endpoint = str(safe_config.get("endpoint") or "")
            allowed_host = str(safe_config.get("allowed_host") or "").casefold()
            if (urlsplit(endpoint).hostname or "").casefold() != allowed_host:
                raise IntegrationContractError("SIEM endpoint must match its explicit allowlist host")
            validate_https_endpoint(endpoint, allowed_hosts=(allowed_host,))
            selected_host = allowed_host
        deployment_hosts = {
            host.rstrip(".").casefold()
            for host in settings.INTEGRATION_OUTBOUND_ALLOWED_HOSTS
        }
        if selected_host != "api.github.com" and selected_host not in deployment_hosts:
            raise IntegrationContractError(
                "integration endpoint is not approved by the deployment outbound policy"
            )
        deployment_pins = {
            host.rstrip(".").casefold(): tuple(addresses)
            for host, addresses in settings.INTEGRATION_OUTBOUND_HOST_PINS.items()
        }
        selected_pins = tuple(sorted(deployment_pins.get(selected_host, ())))
        safe_config["outbound_policy_revision"] = (
            settings.INTEGRATION_OUTBOUND_POLICY_REVISION
        )
        safe_config["outbound_policy_fingerprint"] = stable_idempotency_key(
            "outbound-policy",
            settings.INTEGRATION_OUTBOUND_POLICY_REVISION,
            selected_host,
            ",".join(selected_pins) or "public-dns",
        )
        return safe_config, {str(key): str(value) for key, value in secret_values.items()}

    async def create_principal(
        self,
        *,
        tenant_id: uuid.UUID,
        kind: str,
        display_name: str,
        config: Mapping[str, Any],
        secret_values: Mapping[str, str],
        actor_user_id: int,
    ) -> db_models.IntegrationServicePrincipal:
        safe_config, normalized_secrets = self.validate_configuration(
            kind=kind, config=config, secret_values=secret_values
        )
        ciphertext, fingerprint = encrypt_integration_secrets(normalized_secrets)
        return await self.repo.create_principal(
            tenant_id=tenant_id,
            kind=kind,
            display_name=display_name.strip(),
            config=safe_config,
            secrets_encrypted=ciphertext,
            secret_fingerprint=fingerprint,
            created_by_user_id=actor_user_id,
        )

    async def grant_feature(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        feature: str,
        scope: dict[str, Any],
        actor_user_id: int,
    ) -> db_models.IntegrationGrant:
        principal = await self.repo.get_principal(
            tenant_id=tenant_id, principal_id=principal_id, active_only=True
        )
        if principal is None:
            raise LookupError("integration principal not found")
        if feature not in FEATURES_BY_KIND[principal.kind]:
            raise IntegrationContractError(
                "feature is not permitted for this integration principal kind"
            )
        if not scope:
            raise IntegrationContractError("integration grant scope is required")
        normalized_scope = _normalize_grant_scope(
            principal=principal, feature=feature, scope=scope
        )
        return await self.repo.grant_feature(
            tenant_id=tenant_id,
            principal_id=principal_id,
            feature=feature,
            scope=normalized_scope,
            actor_user_id=actor_user_id,
        )

    async def enqueue_event(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        required_feature: str,
        event_type: str,
        business_key: str,
        payload: dict[str, Any],
        occurred_at: datetime | None = None,
    ) -> tuple[db_models.IntegrationOutbox, bool]:
        principal = await self.repo.get_principal(
            tenant_id=tenant_id, principal_id=principal_id, active_only=True
        )
        if principal is None:
            raise LookupError("integration principal not found")
        if required_feature not in FEATURES_BY_KIND[principal.kind] or not await self.repo.has_active_grant(
            tenant_id=tenant_id,
            principal_id=principal_id,
            feature=required_feature,
            event_type=event_type if required_feature == "siem_emit" else None,
            lock=True,
        ):
            raise PermissionError("integration feature grant is missing or revoked")
        timestamp = occurred_at or datetime.now(timezone.utc)
        return await self.repo.enqueue(
            tenant_id=tenant_id,
            principal_id=principal_id,
            event_type=event_type,
            idempotency_key=stable_idempotency_key(
                tenant_id, principal_id, event_type, business_key
            ),
            nonce=secrets.token_urlsafe(24),
            occurred_at=timestamp,
            payload=payload,
        )

    async def enqueue_persisted_policy_event(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        scan_id: uuid.UUID,
    ) -> tuple[db_models.IntegrationOutbox, bool]:
        scan = await self.repo.db.scalar(
            select(db_models.Scan).where(
                db_models.Scan.id == scan_id,
                db_models.Scan.tenant_id == tenant_id,
            )
        )
        if scan is None or scan.current_attempt_id is None:
            raise LookupError("scan or current attempt not found")
        evaluation = await self.repo.db.scalar(
            select(db_models.FindingPolicyEvaluation)
            .where(
                db_models.FindingPolicyEvaluation.tenant_id == tenant_id,
                db_models.FindingPolicyEvaluation.scan_id == scan_id,
                db_models.FindingPolicyEvaluation.attempt_id == scan.current_attempt_id,
            )
            .order_by(db_models.FindingPolicyEvaluation.created_at.desc())
        )
        if evaluation is None:
            raise LookupError("persisted policy evaluation not found")
        return await self.enqueue_event(
            tenant_id=tenant_id,
            principal_id=principal_id,
            required_feature="siem_emit",
            event_type="policy.evaluated",
            business_key=str(evaluation.id),
            occurred_at=evaluation.created_at,
            payload={
                "scan_id": str(scan_id),
                "attempt_id": str(scan.current_attempt_id),
                "policy_evaluation_id": str(evaluation.id),
                "policy_version_id": str(evaluation.policy_version_id),
                "outcome": evaluation.outcome,
                "coverage_complete": evaluation.coverage_complete,
                "blocking_finding_count": len(evaluation.blocking_fingerprints),
                "waived_finding_count": len(evaluation.waived_fingerprints),
                "authorized_view": f"/analysis/results/{scan_id}",
            },
        )

    async def enqueue_ticket_sync(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        canonical_root_id: str,
        title: str,
        severity: str,
        status: str,
        waiver_expires_at: datetime | None,
        reason: str,
        authorized_view: str,
    ) -> tuple[db_models.IntegrationOutbox, bool]:
        if len(canonical_root_id) > 128 or not canonical_root_id:
            raise IntegrationContractError("canonical finding root is invalid")
        return await self.enqueue_event(
            tenant_id=tenant_id,
            principal_id=principal_id,
            required_feature="ticket_sync",
            event_type="finding.ticket.sync",
            business_key=f"{canonical_root_id}:{status}:{waiver_expires_at or 'none'}",
            payload={
                "canonical_root_id": canonical_root_id,
                "title": title[:255],
                "severity": severity[:16],
                "status": status[:64],
                "waiver_expires_at": waiver_expires_at.isoformat()
                if waiver_expires_at
                else None,
                "reason": reason[:96],
                "authorized_view": authorized_view[:1024],
            },
        )

    async def accept_github_webhook(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        delivery_id: str,
        event_type: str,
        signature: str,
        body: bytes,
        received_at: datetime | None = None,
    ) -> tuple[db_models.IntegrationInboundReceipt, bool, dict[str, Any]]:
        principal = await self.repo.get_principal(
            tenant_id=tenant_id, principal_id=principal_id, active_only=True
        )
        if principal is None or principal.kind != "github_app":
            raise LookupError("GitHub App principal not found")
        if not await self.repo.has_active_grant(
            tenant_id=tenant_id,
            principal_id=principal_id,
            feature="webhook_metadata_read",
            lock=True,
        ):
            raise PermissionError("GitHub webhook metadata grant is missing")
        connector_secrets = decrypt_integration_secrets(principal.secrets_encrypted)
        verify_github_webhook_signature(
            secret=connector_secrets["webhook_secret"], body=body, signature=signature
        )
        if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", delivery_id) or not re.fullmatch(
            r"[a-z][a-z0-9_]{0,95}", event_type
        ):
            raise IntegrationContractError("GitHub delivery metadata is invalid")
        try:
            raw = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrationContractError("GitHub webhook body must be JSON") from exc
        if not isinstance(raw, Mapping):
            raise IntegrationContractError("GitHub webhook body must be an object")
        repository = raw.get("repository") if isinstance(raw.get("repository"), Mapping) else {}
        expected_repository = (
            f"{principal.config['owner']}/{principal.config['repository']}".casefold()
        )
        if str(repository.get("full_name") or "").casefold() != expected_repository:
            raise IntegrationContractError(
                "GitHub webhook repository is outside the connector grant scope"
            )
        metadata = redact_integration_payload(
            {
                "action": raw.get("action"),
                "ref": raw.get("ref"),
                "after": raw.get("after"),
                "repository": {
                    "id": repository.get("id"),
                    "full_name": repository.get("full_name"),
                    "private": repository.get("private"),
                },
            }
        )
        timestamp = received_at or datetime.now(timezone.utc)
        receipt, created = await self.repo.record_inbound_receipt(
            tenant_id=tenant_id,
            principal_id=principal_id,
            source_event_id=delivery_id,
            nonce=delivery_id,
            event_type=f"github.{event_type}",
            digest=payload_digest(metadata),
            occurred_at=timestamp,
        )
        return receipt, created, metadata

    async def download_github_source(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        commit_sha: str,
        http: PinnedHttpClient,
    ) -> bytes:
        principal = await self.repo.get_principal(
            tenant_id=tenant_id, principal_id=principal_id, active_only=True
        )
        if principal is None or principal.kind != "github_app":
            raise LookupError("GitHub App principal not found")
        if not await self.repo.has_active_grant(
            tenant_id=tenant_id,
            principal_id=principal_id,
            feature="repository_contents_read",
            lock=True,
        ):
            raise PermissionError("repository contents grant is missing")
        connector_secrets = decrypt_integration_secrets(principal.secrets_encrypted)
        client = GitHubAppClient(http=http)
        token = await client.installation_token(
            app_id=str(principal.config["app_id"]),
            installation_id=str(principal.config["installation_id"]),
            private_key_pem=connector_secrets["private_key_pem"],
            permissions={"contents": "read"},
        )
        return await client.download_repository_archive(
            owner=str(principal.config["owner"]),
            repository=str(principal.config["repository"]),
            commit_sha=commit_sha,
            token=token,
        )

    async def upload_github_sarif(
        self,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        commit_sha: str,
        ref: str,
        sarif: bytes,
        http: PinnedHttpClient,
    ) -> DeliveryResult:
        principal = await self.repo.get_principal(
            tenant_id=tenant_id, principal_id=principal_id, active_only=True
        )
        if principal is None or principal.kind != "github_app":
            raise LookupError("GitHub App principal not found")
        if not await self.repo.has_active_grant(
            tenant_id=tenant_id,
            principal_id=principal_id,
            feature="security_events_write",
            lock=True,
        ):
            raise PermissionError("security events grant is missing")
        connector_secrets = decrypt_integration_secrets(principal.secrets_encrypted)
        client = GitHubAppClient(http=http)
        token = await client.installation_token(
            app_id=str(principal.config["app_id"]),
            installation_id=str(principal.config["installation_id"]),
            private_key_pem=connector_secrets["private_key_pem"],
            permissions={"security_events": "write"},
        )
        return await client.upload_sarif(
            owner=str(principal.config["owner"]),
            repository=str(principal.config["repository"]),
            commit_sha=commit_sha,
            ref=ref,
            sarif=sarif,
            token=token,
        )
