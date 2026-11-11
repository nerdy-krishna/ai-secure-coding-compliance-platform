"""Is the asset there — and how sure are we?

The cheapest question in the whole inventory, and the one that was never asked: a probe ran
nmap, whatweb and nuclei against an address that was down, and reported "0 services, 0
products" as if that were an answer.

The first version of this module asked a narrower question than the operator needs: it tried
three guessed ports and called silence "unreachable". That is wrong in both directions. A
*refused* connection proves the host is alive (a TCP stack sent a RST back), and a timeout
proves nothing at all — a firewall that drops packets looks exactly like an empty address.
A managed SQL server with only 5432 open was reported unreachable; a hardened appliance that
answers ARP and nothing else was reported unreachable.

So reachability is a ladder, and each level is only climbed when the previous one could not
answer. Level 1 costs milliseconds, level 4 a few seconds, and every level records what it
found and how it found it.

| Level | Question | Method | Cost |
|---|---|---|---|
| 1 | does a port we already know about answer? | TCP connect to recorded/learned ports | ms |
| 2 | does anything answer on a port this kind of asset usually has? | kind profile + nmap top-20 | ~3 s |
| 3 | is the host on the network at all? | `nmap -sn --reason` (ICMP/TCP/UDP/ARP pings) | ~3 s |
| 4 | does a UDP service answer? | `nmap -sn -PU53,123,161` | ~3 s |

A refusal at any level is an answer: the host is up. So is an nmap `conn-refused`,
`arp-response`, `echo-reply` or `syn-ack`. What we do *not* do is turn silence into `down`:
silence is `filtered`, and only a routing error (or a name that will not resolve) is `down`.

The distinction is not academic — it decides what the next stage may do:

- `up` → fingerprint normally.
- `filtered` → a reduced scan (host discovery and the top ports only); no whatweb, no nuclei.
  A filtered host is often the hardened one you actually care about.
- `down` → skip the scanners. This was the original point.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import socket
import time
from typing import Any, Iterable, Optional
from uuid import UUID

from sqlalchemy import select

from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

#: Fast enough to fail quickly, patient enough for a slow SYN-ACK.
CONNECT_TIMEOUT = 3.0
DNS_TIMEOUT = 3.0
NMAP_TIMEOUT = 25.0

#: Level 2 fallback when the inventory says nothing about ports. The nmap top-20, which is
#: the same list nmap itself pings when it has no other reason to believe a host exists.
TOP_PORTS = (
    80, 443, 22, 21, 23, 25, 53, 110, 111, 135,
    139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
)

#: What an asset of each kind plausibly listens on, before anything has been discovered.
#: Ordered by likelihood — the first hit wins and the rest cost nothing.
KIND_PORTS: dict[str, tuple[int, ...]] = {
    "web_app": (443, 80, 8443, 8080),
    "api": (443, 8080, 8443, 8000),
    "host": (22, 3389, 5985, 80, 443),
    "vm": (22, 3389, 5985, 80, 443),
    "service": (443, 80, 22),
    "container": (443, 80, 8080),
    "k8s": (6443, 2375, 10250, 443),
    "database": (5432, 1433, 3306, 1521, 27017, 6379, 9200, 11211),
    "firewall": (443, 8443, 22, 4443),
    "network": (22, 443, 161, 8443),
    "repo": (443, 22),
    "cloud": (443,),
}
DEFAULT_PORTS = (443, 80, 22)

UDP_PORTS = (53, 123, 161)

#: Per-port classification. "refused" is an answer — the host replied with a RST.
OPEN = "open"
REFUSED = "refused"
FILTERED = "filtered"
UNREACHABLE = "unreachable"
ERROR = "error"

#: Overall states.
UP = "up"
DOWN = "down"
UNKNOWN = "unknown"

#: What the next stage may do, given the reachability outcome.
SCAN_FULL = "full"
SCAN_REDUCED = "reduced"
SCAN_SKIP = "skip"

_LEVEL_NAMES = {
    1: "recorded ports",
    2: "standard ports",
    3: "host discovery",
    4: "udp discovery",
}


def nmap_available() -> bool:
    """Levels 3 and 4 need nmap. The API container has no scanners; the engine does."""
    return shutil.which("nmap") is not None


def level_name(level: int) -> str:
    return _LEVEL_NAMES.get(level, f"level {level}")


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


async def _connect(host: str, port: int) -> str:
    """One TCP connect, classified. The difference between RST and silence is the point."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return OPEN
    except ConnectionRefusedError:
        # Nothing is listening, but a TCP stack answered: the host exists.
        return REFUSED
    except (OSError, asyncio.TimeoutError) as exc:
        code = getattr(exc, "errno", None)
        if code in (101, 113):  # ENETUNREACH, EHOSTUNREACH
            return UNREACHABLE
        return FILTERED
    except Exception:  # noqa: BLE001
        return ERROR


async def probe_ports(host: str, ports: Iterable[int]) -> dict[str, Any]:
    """Try each port in parallel and keep every classification, not just the first win."""
    candidates = [int(port) for port in ports if port]
    started = time.perf_counter()
    states = await asyncio.gather(*(_connect(host, port) for port in candidates))
    by_port = {port: state for port, state in zip(candidates, states)}
    elapsed = round(time.perf_counter() - started, 2)

    open_port = next((port for port, state in by_port.items() if state == OPEN), None)
    refused = sorted(port for port, state in by_port.items() if state == REFUSED)
    return {
        "ports": by_port,
        "open_port": open_port,
        "refused_ports": refused,
        # A refusal on any port proves the host is up even when every other port drops.
        "alive": open_port is not None or bool(refused),
        "seconds": elapsed,
    }


_NMAP_UP = re.compile(r"Host is up(?:, received ([a-z0-9\-]+))?")
_NMAP_DOWN = re.compile(r"Host seems down")


def parse_nmap_discovery(output: str) -> dict[str, Any]:
    """Read nmap's own verdict, including *why* it believes the host is up.

    `--reason` is what makes this worth a subprocess: "arp-response" on a filtered host is a
    firmer answer than anything we can get from TCP.
    """
    up = _NMAP_UP.search(output or "")
    if up:
        mechanism = (up.group(1) or "echo-reply").strip()
        return {"alive": True, "mechanism": mechanism}
    if _NMAP_DOWN.search(output or ""):
        return {"alive": False, "mechanism": "host seems down"}
    return {"alive": None, "mechanism": "no verdict"}


async def _nmap(host: str, *, udp: bool = False) -> dict[str, Any]:
    """Run `nmap -sn --reason`. Returns the parsed verdict; failures are not fatal."""
    cmd = [
        "nmap",
        "-sn",
        "--reason",
        "-PE",
        "-PP",
        "-PS22,80,443,445,3389,5432,1433,3306,8080",
        "-PA80,443",
        "--host-timeout",
        "15s",
    ]
    if udp:
        cmd += ["-PU" + ",".join(str(port) for port in UDP_PORTS)]
    cmd.append(host)
    started = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        raw, _ = await asyncio.wait_for(proc.communicate(), timeout=NMAP_TIMEOUT)
    except FileNotFoundError:
        return {"alive": None, "mechanism": "nmap not installed", "seconds": 0.0}
    except asyncio.TimeoutError:
        return {"alive": None, "mechanism": "nmap timed out", "seconds": round(NMAP_TIMEOUT, 1)}
    except Exception:  # noqa: BLE001
        logger.warning("nmap discovery failed for %s", host, exc_info=True)
        return {"alive": None, "mechanism": "nmap error", "seconds": 0.0}

    verdict = parse_nmap_discovery(raw.decode("utf-8", "replace"))
    verdict["seconds"] = round(time.perf_counter() - started, 2)
    return verdict


def scan_policy(outcome: dict[str, Any]) -> str:
    """What may run next. Only a proven absence skips the scanners."""
    state = outcome.get("state")
    if state == UP:
        return SCAN_FULL
    if state == DOWN:
        return SCAN_SKIP
    # Filtered: nothing answered, but nothing said the host is absent. Scan cheaply, and let
    # the port scan itself become the discovery mechanism.
    return SCAN_REDUCED


async def check_host(
    host: str,
    ports: Optional[list[int]] = None,
    *,
    kind: Optional[str] = None,
    max_level: int = 4,
) -> dict[str, Any]:
    """Climb the ladder until something answers, or until we run out of questions."""
    started = time.perf_counter()
    if not host:
        return {
            "reachable": False,
            "state": DOWN,
            "reason": "no_host",
            "port": None,
            "level": 0,
            "evidence": "no host recorded",
            "ports_tried": [],
            "seconds": 0.0,
        }

    resolved, dns_reason = await _resolve(host)
    if not resolved:
        return {
            "reachable": False,
            "state": DOWN,
            "reason": dns_reason,
            "port": None,
            "level": 1,
            "evidence": f"name did not resolve ({dns_reason})",
            "ports_tried": [],
            "seconds": round(time.perf_counter() - started, 2),
        }

    def outcome(**kwargs: Any) -> dict[str, Any]:
        base = {
            "port": None,
            "level": 1,
            "evidence": "",
            "ports_tried": [],
        }
        base.update(kwargs)
        base["seconds"] = round(time.perf_counter() - started, 2)
        base["reachable"] = base["state"] == UP
        return base

    # Level 1 — ports the inventory already knows about.
    known = [int(port) for port in (ports or []) if port]
    if known and max_level >= 1:
        found = await probe_ports(host, known)
        if found["alive"]:
            return outcome(
                state=UP,
                reason=None,
                port=found["open_port"] or found["refused_ports"][0],
                level=1,
                evidence=(
                    f"port {found['open_port']} accepted a connection"
                    if found["open_port"]
                    else f"port {found['refused_ports'][0]} refused a connection"
                ),
                ports_tried=sorted(found["ports"]),
            )
        if all(state == UNREACHABLE for state in found["ports"].values()):
            return outcome(
                state=DOWN,
                reason="no_route",
                level=1,
                evidence="the network reported the address unreachable",
                ports_tried=sorted(found["ports"]),
            )

    # Level 2 — the ports this kind of asset usually serves, then the nmap top-20.
    if max_level >= 2:
        profile = list(KIND_PORTS.get((kind or "").strip(), ())) or list(DEFAULT_PORTS)
        candidates = [port for port in profile if port not in known]
        candidates += [port for port in TOP_PORTS if port not in known and port not in candidates]
        found = await probe_ports(host, candidates)
        if found["alive"]:
            return outcome(
                state=UP,
                reason=None,
                port=found["open_port"] or found["refused_ports"][0],
                level=2,
                evidence=(
                    f"port {found['open_port']} accepted a connection"
                    if found["open_port"]
                    else f"port {found['refused_ports'][0]} refused a connection"
                ),
                ports_tried=sorted(found["ports"]),
            )
        if found["ports"] and all(state == UNREACHABLE for state in found["ports"].values()):
            return outcome(
                state=DOWN,
                reason="no_route",
                level=2,
                evidence="the network reported the address unreachable",
                ports_tried=sorted(found["ports"]),
            )

    # Levels 3 and 4 need nmap, which only the engine image ships. Reporting "nmap saw no
    # host" from a container that has no nmap would be a lie, so the ladder stops at what
    # this process can actually do.
    can_nmap = nmap_available()
    reached_level = 2 if max_level >= 2 else max_level

    # Level 3 — ask nmap whether the host is on the network at all.
    if max_level >= 3 and can_nmap:
        verdict = await _nmap(host)
        reached_level = 3
        if verdict.get("alive") is True:
            return outcome(
                state=UP,
                reason=None,
                level=3,
                evidence=f"nmap: host is up ({verdict['mechanism']})",
                ports_tried=[],
            )

    # Level 4 — a UDP service may be the only thing listening.
    if max_level >= 4 and can_nmap:
        verdict = await _nmap(host, udp=True)
        reached_level = 4
        if verdict.get("alive") is True:
            return outcome(
                state=UP,
                reason=None,
                level=4,
                evidence=f"nmap: host is up ({verdict['mechanism']})",
                ports_tried=[],
            )

    # Nothing answered. That is not the same as absent: an address that drops packets and a
    # host with no open TCP port are indistinguishable from here, so say "filtered".
    return outcome(
        state=UNKNOWN,
        reason="filtered",
        level=reached_level,
        evidence=(
            "no port answered and nmap saw no host — packets are likely filtered"
            if can_nmap
            else "no TCP port answered and nmap is unavailable here, so the host "
            "cannot be confirmed either way"
        ),
        ports_tried=[],
    )


def is_proven_down(outcome: dict[str, Any]) -> bool:
    return outcome.get("state") == DOWN


async def remember(asset_id: UUID, outcome: dict[str, Any]) -> None:
    """Store the outcome on the asset, and keep the port that answered."""
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
            asset.last_probe_level = int(outcome.get("level") or 0) or None
            asset.last_probe_evidence = (str(outcome.get("evidence") or "") or None)
            if asset.last_probe_evidence:
                asset.last_probe_evidence = asset.last_probe_evidence[:200]

            # Learn: a port that just answered is the cheapest possible probe next time.
            port = outcome.get("port")
            if port:
                known = await db.scalar(
                    select(am.AssetService.id).where(
                        am.AssetService.asset_id == asset_id,
                        am.AssetService.port == int(port),
                    )
                )
                host = (outcome.get("host") or "").strip()
                if known is None and host:
                    db.add(
                        am.AssetService(
                            asset_id=asset_id,
                            host=host,
                            port=int(port),
                            protocol="tcp",
                            source="reachability",
                            confidence="heuristic",
                        )
                    )
            await db.commit()
    except Exception:  # noqa: BLE001 — a status write must not fail a probe
        logger.warning("could not record reachability for %s", asset_id, exc_info=True)


async def ports_for_asset(asset_id: UUID) -> list[int]:
    async with AsyncSessionLocal() as db:
        rows = await db.scalars(
            select(am.AssetService.port).where(am.AssetService.asset_id == asset_id)
        )
        return sorted({int(port) for port in rows if port})


async def context_for_asset(asset_id: UUID) -> dict[str, Any]:
    """Everything the ladder needs about one asset: its hosts, known ports and kind.

    An asset usually carries more than one host — the name it was created with, plus each
    discovered endpoint. The order matters: a host with a port is a better guess than a bare
    name, and an unresolvable name must not hide a resolvable endpoint, so `check_asset`
    walks the list rather than trusting the first row.
    """
    async with AsyncSessionLocal() as db:
        asset = await db.get(am.Asset, asset_id)
        if asset is None:
            return {}
        rows = list(
            await db.scalars(
                select(am.AssetService)
                .where(am.AssetService.asset_id == asset_id)
                .order_by(am.AssetService.port.is_(None), am.AssetService.first_seen)
            )
        )
        hosts: list[str] = []
        for row in rows:
            host = (row.host or "").strip()
            if host and host.lower() not in {seen.lower() for seen in hosts}:
                hosts.append(host)
        if asset.name and asset.name.strip().lower() not in {seen.lower() for seen in hosts}:
            hosts.append(asset.name.strip())
        ports = sorted({int(row.port) for row in rows if row.port})
        return {
            "host": hosts[0] if hosts else "",
            "hosts": hosts,
            "ports": ports,
            "kind": asset.kind,
            "name": asset.name,
        }


async def check_asset(asset_id: UUID, *, max_level: int = 4) -> dict[str, Any]:
    """Climb the ladder over the asset's hosts, stopping at the first that answers."""
    context = await context_for_asset(asset_id)
    if not context:
        return {"state": DOWN, "reachable": False, "reason": "no_asset", "level": 0,
                "evidence": "asset not found", "port": None, "seconds": 0.0, "host": ""}
    if not context.get("hosts"):
        return {"state": DOWN, "reachable": False, "reason": "no_host", "level": 0,
                "evidence": "no host recorded", "port": None, "seconds": 0.0, "host": ""}

    attempts: list[dict[str, Any]] = []
    spent = 0.0
    for host in context["hosts"]:
        outcome = await check_host(host, context["ports"], kind=context["kind"],
                                   max_level=max_level)
        spent += float(outcome.get("seconds") or 0.0)
        outcome["host"] = host
        attempts.append(outcome)
        if outcome.get("state") == UP:
            return outcome
        # A name that does not resolve says nothing about the next host; try it. A host that
        # the network calls unreachable ends the walk — the path is gone for all of them.
        if outcome.get("reason") == "no_route":
            break

    best = attempts[0]
    # Report the most informative failure, and keep the total cost across hosts.
    for attempt in attempts:
        if attempt.get("reason") != "dns_failed" and best.get("reason") == "dns_failed":
            best = attempt
    best = dict(best)
    best["seconds"] = round(spent, 2)
    best["attempts"] = [
        {"host": item["host"], "state": item["state"], "reason": item["reason"]}
        for item in attempts
    ]
    return best


async def host_for_asset(asset: am.Asset) -> Optional[str]:
    """The address to try: the first recorded endpoint host, else the asset's own name."""
    async with AsyncSessionLocal() as db:
        host = await db.scalar(
            select(am.AssetService.host)
            .where(am.AssetService.asset_id == asset.id, am.AssetService.host.isnot(None))
            .limit(1)
        )
    return host or (asset.name if asset.name and "." in asset.name or asset.name.count(".") == 3 else host)
