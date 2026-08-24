"""Security contract for outbound enterprise-integration events.

Only the redacted payload returned by :func:`redact_integration_payload` may be
persisted in the integration outbox or signed for an external consumer.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import socket
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit


ENVELOPE_VERSION = "sccap.integration.v1"
MAX_CLOCK_SKEW_SECONDS = 300
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_STRING_LENGTH = 2_048
MAX_COLLECTION_ITEMS = 100
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_DENIED_KEY_FRAGMENTS = frozenset(
    {
        "api_key",
        "authorization",
        "credential",
        "password",
        "private_key",
        "prompt",
        "provider_payload",
        "raw_payload",
        "response",
        "secret",
        "source_code",
        "source_text",
        "token",
    }
)


class IntegrationContractError(ValueError):
    """Raised when an integration request fails the wire/security contract."""


@dataclass(frozen=True)
class ResolvedIntegrationEndpoint:
    """A destination whose hostname and connection address were bound once."""

    hostname: str
    port: int
    address: str


@dataclass(frozen=True)
class IntegrationSourceProvenance:
    """Validated immutable source identity included in a scan aggregate commit."""

    tenant_id: uuid.UUID
    provider: str
    commit_sha: str
    ref: str
    repository_slug: str
    trusted_context: bool
    actor_user_id: int

    def __post_init__(self) -> None:
        if self.provider not in {"github", "gitlab", "azure_devops", "bitbucket"}:
            raise IntegrationContractError("unsupported CI source provider")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", self.commit_sha):
            raise IntegrationContractError(
                "CI source requires a full immutable commit SHA"
            )
        if not re.fullmatch(r"refs/(?:heads|tags|pull)/[-A-Za-z0-9_./]+", self.ref):
            raise IntegrationContractError("invalid CI source ref")
        if ".." in self.ref or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository_slug
        ):
            raise IntegrationContractError("invalid CI repository identity")
        if not self.trusted_context or self.actor_user_id <= 0:
            raise IntegrationContractError(
                "CI source provenance requires a trusted actor"
            )


def _is_denied_key(key: object) -> bool:
    normalized = str(key).strip().casefold().replace("-", "_")
    return any(fragment in normalized for fragment in _DENIED_KEY_FRAGMENTS)


def _redact(value: object, *, depth: int) -> Any:
    if depth > 8:
        return "[DEPTH_LIMIT]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_STRING_LENGTH]
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_COLLECTION_ITEMS:
                redacted["_truncated"] = True
                break
            safe_key = str(key)[:128]
            if _is_denied_key(key):
                continue
            redacted[safe_key] = _redact(item, depth=depth + 1)
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [_redact(item, depth=depth + 1) for item in value[:MAX_COLLECTION_ITEMS]]
    return str(value)[:MAX_STRING_LENGTH]


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise IntegrationContractError("integration payload exceeds 64 KiB")
    return encoded


def redact_integration_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a bounded copy with source, model, provider, and secret data removed."""

    redacted = _redact(payload, depth=0)
    if not isinstance(redacted, dict):  # pragma: no cover - Mapping guarantees this
        raise IntegrationContractError("integration payload must be an object")
    canonical_json_bytes(redacted)
    return redacted


def stable_idempotency_key(*parts: object) -> str:
    normalized = [str(part).strip() for part in parts]
    if not normalized or any(not part for part in normalized):
        raise IntegrationContractError("idempotency components must be non-empty")
    return hashlib.sha256(canonical_json_bytes({"parts": normalized})).hexdigest()


def build_envelope(
    *,
    event_id: str,
    event_type: str,
    tenant_id: str,
    nonce: str,
    timestamp: int,
    idempotency_key: str,
    payload: Mapping[str, Any],
    occurred_at: datetime | None = None,
    delivery_attempt: int = 1,
) -> dict[str, Any]:
    if not _NONCE_PATTERN.fullmatch(nonce):
        raise IntegrationContractError("nonce must be 128+ bits of base64url data")
    if timestamp <= 0:
        raise IntegrationContractError("timestamp must be a positive Unix timestamp")
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,95}", event_type):
        raise IntegrationContractError("invalid event type")
    if not re.fullmatch(r"[0-9a-f]{64}", idempotency_key):
        raise IntegrationContractError("invalid idempotency key")
    if delivery_attempt < 1:
        raise IntegrationContractError("delivery attempt must be positive")
    event_time = occurred_at or datetime.fromtimestamp(timestamp, timezone.utc)
    if event_time.tzinfo is None:
        raise IntegrationContractError("occurred_at must be timezone-aware")
    envelope = {
        "version": ENVELOPE_VERSION,
        "event_id": str(event_id),
        "event_type": event_type,
        "tenant_id": str(tenant_id),
        "occurred_at": event_time.astimezone(timezone.utc).isoformat(),
        "sent_at": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "timestamp": timestamp,
        "nonce": nonce,
        "delivery_attempt": delivery_attempt,
        "idempotency_key": idempotency_key,
        "payload": redact_integration_payload(payload),
    }
    canonical_json_bytes(envelope)
    return envelope


def sign_envelope(secret: str, envelope: Mapping[str, Any]) -> str:
    if len(secret.encode("utf-8")) < 32:
        raise IntegrationContractError("webhook signing secret must contain 32 bytes")
    timestamp = int(envelope.get("timestamp") or 0)
    body = canonical_json_bytes(envelope)
    signed = f"{timestamp}.".encode("ascii") + body
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def verify_envelope_signature(
    *,
    secret: str,
    envelope: Mapping[str, Any],
    signature: str,
    now: datetime | None = None,
    max_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
) -> None:
    fields: dict[str, str] = {}
    for item in signature.split(","):
        name, separator, value = item.partition("=")
        if separator and name not in fields:
            fields[name] = value
    if not fields.get("t", "").isdigit() or not re.fullmatch(
        r"[0-9a-f]{64}", fields.get("v1", "")
    ):
        raise IntegrationContractError("invalid webhook signature header")
    timestamp = int(fields["t"])
    if timestamp != int(envelope.get("timestamp") or 0):
        raise IntegrationContractError("signature timestamp does not match envelope")
    reference = int((now or datetime.now(timezone.utc)).timestamp())
    if abs(reference - timestamp) > max_skew_seconds:
        raise IntegrationContractError("webhook timestamp is outside the replay window")
    expected = sign_envelope(secret, envelope).split("v1=", 1)[1]
    if not hmac.compare_digest(expected, fields["v1"]):
        raise IntegrationContractError("webhook signature mismatch")


def retry_delay_seconds(attempt: int, *, base: int = 5, cap: int = 3_600) -> int:
    if attempt < 1:
        raise IntegrationContractError("attempt must be positive")
    return min(cap, base * (2 ** min(attempt - 1, 16)))


def payload_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def validate_https_endpoint(
    url: str, *, allowed_hosts: Sequence[str]
) -> tuple[str, int]:
    """Validate a connector URL before DNS resolution or external I/O."""

    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise IntegrationContractError("invalid integration endpoint") from exc
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise IntegrationContractError(
            "integration endpoint must be credential-free HTTPS"
        )
    host = (parsed.hostname or "").rstrip(".").casefold()
    normalized_hosts = {item.rstrip(".").casefold() for item in allowed_hosts}
    if not host or host not in normalized_hosts:
        raise IntegrationContractError("integration endpoint host is not allowlisted")
    if parsed.port not in (None, 443):
        raise IntegrationContractError("integration endpoint must use port 443")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise IntegrationContractError("integration endpoint cannot use an IP literal")
    return host, 443


async def assert_public_endpoint(
    url: str,
    *,
    allowed_hosts: Sequence[str],
    resolver: Callable[[str, int], Awaitable[Sequence[str]]] | None = None,
) -> None:
    """Reject DNS answers that can reach loopback, link-local, or private networks.

    This helper validates resolution only. Outbound HTTP must use
    :func:`resolve_integration_endpoint` and connect to its returned address so
    that a second DNS lookup cannot create a rebinding window.
    """

    await resolve_integration_endpoint(
        url,
        allowed_hosts=allowed_hosts,
        resolver=resolver,
    )


async def resolve_integration_endpoint(
    url: str,
    *,
    allowed_hosts: Sequence[str],
    host_pins: Mapping[str, Sequence[str]] | None = None,
    resolver: Callable[[str, int], Awaitable[Sequence[str]]] | None = None,
) -> ResolvedIntegrationEndpoint:
    """Resolve once and return the exact IP an HTTP transport must connect to.

    Unpinned destinations must resolve exclusively to globally routable IPs.
    Private on-prem destinations are supported only through operator-owned,
    exact hostname-to-IP pins; loopback, link-local, multicast, unspecified,
    and reserved addresses are never accepted, even when pinned.
    """

    host, port = validate_https_endpoint(url, allowed_hosts=allowed_hosts)

    async def default_resolver(name: str, target_port: int) -> Sequence[str]:
        import asyncio

        infos = await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: socket.getaddrinfo(name, target_port, type=socket.SOCK_STREAM),
        )
        return sorted({str(info[4][0]) for info in infos})

    normalized_pins = {
        str(name).rstrip(".").casefold(): tuple(str(address) for address in addresses)
        for name, addresses in (host_pins or {}).items()
    }
    explicitly_pinned = host in normalized_pins
    addresses = (
        normalized_pins[host]
        if explicitly_pinned
        else await (resolver or default_resolver)(host, port)
    )
    if not addresses:
        raise IntegrationContractError("integration endpoint did not resolve")
    validated: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise IntegrationContractError(
                "integration endpoint returned an invalid IP"
            ) from exc
        prohibited = (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        )
        if prohibited or (not explicitly_pinned and not ip.is_global):
            raise IntegrationContractError(
                "integration endpoint resolved to a non-public address"
            )
        validated.append(ip)
    selected = sorted(validated, key=lambda item: (item.version, int(item)))[0]
    return ResolvedIntegrationEndpoint(hostname=host, port=port, address=str(selected))
