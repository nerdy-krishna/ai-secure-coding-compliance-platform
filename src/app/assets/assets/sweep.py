"""Inventory sweeps: refresh what the assets are, then apply a CVE list.

A sweep is the answer to "check my whole organisation against these CVEs". It does
two things per asset, in order:

1. **Fingerprint** — a read-only request to each recorded endpoint to refresh the
   product and version the inventory knows about. This is what the inventory's
   authorisation buys: an in-scope asset's own hosts may be looked at.
2. **Match** — apply the CVE list (or the whole corpus) to the refreshed inventory,
   optionally verifying the candidates a version alone cannot settle.

The sweep is deliberately not a pentest. It does not use the offensive toolset, does
not chain exploits and does not touch anything outside the asset's recorded hosts.
A finding that looks exploitable becomes a pentest run, which is where destructive
testing is authorised (ADR-028).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional
from urllib.parse import urlparse
from uuid import UUID

import httpx
from sqlalchemy import select

from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

SWEEP_TIMEOUT = 20.0
SWEEP_MAX_BODY = 200_000

# `<meta name="generator" content="WordPress 6.2">`, `X-Generator: Drupal 10`.
_GENERATOR_RE = re.compile(
    r"content=\"([^\"\\]{3,120})\"", re.IGNORECASE
)
_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9._+-]{1,40})[/\s](\d+\.\d+(?:\.\d+)?[A-Za-z0-9.+-]*)")
_SERVER_PRODUCTS = ("nginx", "apache", "microsoft-iis", "lighttpd", "caddy", "openresty")


def _endpoint(service: am.AssetService) -> str:
    scheme = service.protocol if service.protocol in ("http", "https") else "https"
    default_port = (scheme == "https" and service.port == 443) or (
        scheme == "http" and service.port == 80
    )
    url = f"{scheme}://{service.host}"
    if service.port and not default_port:
        url += f":{service.port}"
    if service.path:
        url += service.path
    return url


def _fingerprint_from_response(response: httpx.Response) -> tuple[Optional[str], Optional[str], str]:
    """(product, version, banner) from headers and the first bytes of the body."""
    server = response.headers.get("server") or ""
    powered = response.headers.get("x-powered-by") or ""
    generator_header = response.headers.get("x-generator") or ""
    banner_bits = [part for part in (server, powered, generator_header) if part]
    product = version = None

    for candidate in (server, powered, generator_header):
        match = _VERSION_RE.search(candidate or "")
        if match:
            product, version = match.group(1), match.group(2)
            break
    if product is None and server:
        lowered = server.lower()
        for known in _SERVER_PRODUCTS:
            if known in lowered:
                product = known
                break

    if version is None:
        body = (response.text or "")[:SWEEP_MAX_BODY]
        for meta in re.finditer(r"<meta[^>]+name=[\"']generator[\"'][^>]*>", body, re.IGNORECASE):
            content = _GENERATOR_RE.search(meta.group(0))
            if not content:
                continue
            match = _VERSION_RE.search(content.group(1))
            if match:
                product, version = match.group(1), match.group(2)
                banner_bits.append(meta.group(0)[:200])
                break

    return product, version, " · ".join(banner_bits)[:500]


async def fingerprint_services(
    services: list[am.AssetService],
) -> list[dict[str, Any]]:
    """Refresh product/version for each endpoint; returns what changed.

    Only the asset's own recorded hosts are requested, one request per endpoint,
    with redirects disabled so a redirect cannot walk the sweep onto another host.
    """
    updates: list[dict[str, Any]] = []
    allowed = {service.host.lower() for service in services}
    async with httpx.AsyncClient(
        timeout=SWEEP_TIMEOUT, follow_redirects=False, verify=False
    ) as client:
        for service in services:
            url = _endpoint(service)
            host = (urlparse(url).hostname or "").lower()
            if host not in allowed:
                continue
            try:
                response = await client.get(url)
            except Exception as exc:  # noqa: BLE001 — an unreachable endpoint is data
                updates.append({"service_id": service.id, "error": f"{type(exc).__name__}: {exc}"})
                continue
            product, version, banner = _fingerprint_from_response(response)
            if not product and not version:
                updates.append(
                    {"service_id": service.id, "error": f"no fingerprint (HTTP {response.status_code})"}
                )
                continue
            service.product = product or service.product
            service.version = version or service.version
            service.banner = banner or service.banner
            service.source = "sweep"
            service.confidence = "heuristic"
            updates.append(
                {
                    "service_id": service.id,
                    "host": service.host,
                    "product": service.product,
                    "version": service.version,
                }
            )
    return updates


async def run_sweep(
    *,
    tenant_id: UUID,
    asset_ids: Optional[list[UUID]] = None,
    cve_ids: Optional[list[str]] = None,
    verify: bool = False,
    max_verifications: int = 25,
) -> dict[str, Any]:
    """Fingerprint every in-scope asset, then apply the CVE list to the inventory."""
    async with AsyncSessionLocal() as db:
        query = select(am.Asset).where(
            am.Asset.tenant_id == tenant_id, am.Asset.in_scope.is_(True)
        )
        if asset_ids:
            query = query.where(am.Asset.id.in_(asset_ids))
        assets = list(await db.scalars(query))

        services_updated = 0
        tasks_run = 0
        for asset in assets:
            services = list(
                await db.scalars(
                    select(am.AssetService).where(am.AssetService.asset_id == asset.id)
                )
            )
            if not services:
                continue
            updates = await fingerprint_services(services)
            await db.commit()
            tasks_run += sum(1 for update in updates if "error" not in update)
            services_updated += sum(1 for update in updates if "error" not in update)

    from app.assets import service as asset_service

    outcome = await asset_service.check_cves(
        tenant_id=tenant_id,
        cve_ids=cve_ids,
        asset_ids=[asset.id for asset in assets] or None,
        verify=verify,
        max_verifications=max_verifications,
    )
    return {
        "assets": len(assets),
        "endpoints_fingerprinted": tasks_run,
        "services_updated": services_updated,
        **outcome,
    }
