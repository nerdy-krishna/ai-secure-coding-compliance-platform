"""Verified tenant-domain ownership for SSO routing and JIT provisioning."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

import dns.asyncresolver
import dns.exception
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models


_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TXT_PREFIX = "sccap-domain-verification="


class DomainVerificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DomainChallenge:
    token: str
    token_hash: str
    txt_name: str
    txt_value: str


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or candidate.startswith("*.") or "@" in candidate:
        raise DomainVerificationError("domain must be a DNS name without wildcard")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise DomainVerificationError("IP addresses cannot be verified domains")
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainVerificationError("domain is not valid IDNA") from exc
    labels = ascii_domain.split(".")
    if len(labels) < 2 or len(ascii_domain) > 253:
        raise DomainVerificationError("domain must be a fully qualified DNS name")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise DomainVerificationError("domain contains an invalid DNS label")
    return ascii_domain


def new_challenge(domain: str) -> DomainChallenge:
    normalized = normalize_domain(domain)
    token = secrets.token_urlsafe(32)
    return DomainChallenge(
        token=token,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        txt_name=f"_sccap-domain-verification.{normalized}",
        txt_value=f"{_TXT_PREFIX}{token}",
    )


async def verify_dns_challenge(
    row: db_models.TenantVerifiedDomain,
    *,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> bool:
    dns_resolver = resolver or dns.asyncresolver.Resolver()
    name = f"_sccap-domain-verification.{row.domain}"
    try:
        answers = await dns_resolver.resolve(name, "TXT", lifetime=5.0)
    except (dns.exception.DNSException, TimeoutError):
        return False
    for answer in answers:
        raw_parts = getattr(answer, "strings", ())
        value = b"".join(raw_parts).decode("utf-8", errors="ignore")
        if not value.startswith(_TXT_PREFIX):
            continue
        supplied = hashlib.sha256(value[len(_TXT_PREFIX) :].encode()).hexdigest()
        if hmac.compare_digest(supplied, row.verification_token_hash):
            return True
    return False


async def ensure_verified_provider_domains(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | None,
    allowed_domains: Iterable[str] | None,
    forced_domains: Iterable[str] | None,
    jit_policy: str,
) -> tuple[list[str] | None, list[str] | None]:
    allowed = sorted({normalize_domain(value) for value in (allowed_domains or [])})
    forced = sorted({normalize_domain(value) for value in (forced_domains or [])})
    if not set(forced).issubset(allowed):
        raise DomainVerificationError("force-for-SSO domains must also be allowed")
    if jit_policy in {"auto", "approve"} and not allowed:
        raise DomainVerificationError(
            "automatic or approval-based JIT requires at least one verified domain"
        )
    required = set(allowed) | set(forced)
    if not required:
        return None, None
    if tenant_id is None:
        raise DomainVerificationError("provider must belong to a tenant")
    verified = set(
        (
            await db.scalars(
                select(db_models.TenantVerifiedDomain.domain).where(
                    db_models.TenantVerifiedDomain.tenant_id == tenant_id,
                    db_models.TenantVerifiedDomain.status == "verified",
                    db_models.TenantVerifiedDomain.domain.in_(required),
                )
            )
        ).all()
    )
    missing = sorted(required - verified)
    if missing:
        raise DomainVerificationError(
            "domains are not verified for this tenant: " + ", ".join(missing)
        )
    return allowed or None, forced or None


async def domain_is_verified_for_provider(
    db: AsyncSession,
    provider: db_models.SsoProvider,
    domain: str,
) -> bool:
    if provider.tenant_id is None:
        return False
    normalized = normalize_domain(domain)
    allowed = {normalize_domain(value) for value in provider.allowed_email_domains or []}
    if normalized not in allowed:
        return False
    match = await db.scalar(
        select(db_models.TenantVerifiedDomain.id).where(
            db_models.TenantVerifiedDomain.tenant_id == provider.tenant_id,
            db_models.TenantVerifiedDomain.domain == normalized,
            db_models.TenantVerifiedDomain.status == "verified",
        )
    )
    return match is not None


def mark_verified(row: db_models.TenantVerifiedDomain) -> None:
    row.status = "verified"
    row.verified_at = datetime.now(timezone.utc)
