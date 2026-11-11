"""Is the asset even there?

The cheapest question in the whole inventory, and the one that was never asked: a probe
ran nmap, whatweb and nuclei against an address that was down, and reported "0 services,
0 products" as if that were an answer. Worse, it spent the full tool budget doing it.

A reachability check is deliberately blunt — resolve the name, then open a TCP connection
to the ports the asset actually serves. No ICMP (needs privileges and is often filtered),
no banner, no interpretation. If nothing accepts a connection, the asset is unreachable
and the scanners are skipped, which saves minutes per dead host.

Every attempt is recorded on the asset (`last_probe_at`, `reachable`, `unreachable_reason`,
`last_probe_seconds`), so the list can say "last scanned: 3 minutes ago · unreachable
(connection refused)" instead of showing nothing.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select

from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

#: Fast enough to fail quickly, patient enough for a slow SYN-ACK.
CONNECT_TIMEOUT = 3.0
DNS_TIMEOUT = 3.0
#: When the inventory has no endpoint for an asset, try the ports a service usually lives on.
DEFAULT_PORTS = (443, 80, 22)


async def _resolve(host: str) -> tuple[bool, Optional[str]]:
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=DNS_TIMEOUT
        )
        return True, None
    except asyncio.TimeoutError:
        return False, "dns_timeout"
    except socket.gaierror:
        return False, "dns_failed"
    except Exception:  # noqa: BLE001
        return False, "dns_error"


async def _tcp_open(host: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


async def check_host(
    host: str, ports: Optional[list[int]] = None
) -> dict[str, Any]:
    """Resolve and try to connect. Returns reachable, reason, which port answered, ms."""
    started = time.perf_counter()
    if not host:
        return {"reachable": False, "reason": "no_host", "port": None, "seconds": 0.0}

    resolved, dns_reason = await _resolve(host)
    if not resolved:
        return {
            "reachable": False,
            "reason": dns_reason,
            "port": None,
            "seconds": round(time.perf_counter() - started, 2),
        }

    candidates = [port for port in (ports or []) if port] or list(DEFAULT_PORTS)
    # Parallel: a closed port costs a full timeout when tried in sequence.
    results = await asyncio.gather(*(_tcp_open(host, port) for port in candidates))
    for port, opened in zip(candidates, results):
        if opened:
            return {
                "reachable": True,
                "reason": None,
                "port": port,
                "seconds": round(time.perf_counter() - started, 2),
            }
    return {
        "reachable": False,
        "reason": "no_open_port",
        "port": None,
        "seconds": round(time.perf_counter() - started, 2),
    }


async def remember(asset_id: UUID, outcome: dict[str, Any]) -> None:
    """Store the outcome on the asset so the list can show it."""
    from sqlalchemy import func

    try:
        async with AsyncSessionLocal() as db:
            asset = await db.get(am.Asset, asset_id)
            if asset is None:
                return
            asset.last_probe_at = func.now()
            asset.reachable = bool(outcome.get("reachable"))
            asset.unreachable_reason = (
                None if outcome.get("reachable") else str(outcome.get("reason") or "unknown")[:64]
            )
            asset.last_probe_seconds = float(outcome.get("seconds") or 0.0)
            await db.commit()
    except Exception:  # noqa: BLE001 — a status write must not fail a probe
        logger.warning("could not record reachability for %s", asset_id, exc_info=True)


async def ports_for_asset(asset_id: UUID) -> list[int]:
    async with AsyncSessionLocal() as db:
        rows = await db.scalars(
            select(am.AssetService.port).where(am.AssetService.asset_id == asset_id)
        )
        return sorted({int(port) for port in rows if port})


async def host_for_asset(asset: am.Asset) -> Optional[str]:
    """The address to try: the first recorded endpoint host, else the asset's own name."""
    async with AsyncSessionLocal() as db:
        host = await db.scalar(
            select(am.AssetService.host)
            .where(am.AssetService.asset_id == asset.id, am.AssetService.host.isnot(None))
            .limit(1)
        )
    return host or (asset.name if asset.name and "." in asset.name or asset.name.count(".") == 3 else host)
