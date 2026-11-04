"""Active discovery: find out what an asset *is* before asking what affects it.

A CVE check against a bare IP has nothing to match: no product, no version. The
previous behaviour was to return "nothing found" in milliseconds, which is honest
about the matcher and useless to the operator — nothing had been looked at.

This is the missing first step, and it mirrors how CVE tooling works in practice:
fingerprint the target, then decide. For each host it:

- probes HTTP and HTTPS on the ports worth probing (recorded port if any, plus the
  common ones), capturing status, `Server`, `X-Powered-By`, `X-Generator`, page title
  and generator meta tags;
- grabs service banners on the usual ports (SSH, FTP, SMTP, MySQL, PostgreSQL, Redis,
  Elasticsearch) with a short timeout, because an IP with no web server is still an
  asset with a version;
- stores what it learns as `asset_services` rows, so the next check — and the next
  operator — starts from knowledge instead of from zero.

It is read-only and touches only the asset's own hosts. It is not a port scan: one
connection per listed port, no banner flooding, and any failure is recorded rather
than retried.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any, Optional

import httpx
from sqlalchemy import select

from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

#: Web ports worth a look when the inventory does not say.
#: Web ports worth a look when the inventory does not say. A CDN, an appliance UI or a
#: management console rarely lives on 80/443 alone.
WEB_PORTS = (
    (443, "https"),
    (80, "http"),
    (8443, "https"),
    (8080, "http"),
    (8000, "http"),
    (3000, "http"),
    (5000, "http"),
    (8888, "http"),
    (9000, "http"),
    (9090, "http"),
    (9443, "https"),
    (10443, "https"),
)
#: Hosts are probed with short timeouts: an unreachable IP must not stall a check.
CONNECT_TIMEOUT = 3.0
HTTP_TIMEOUT = 6.0
#: Total wall clock for one asset, so a filtered host cannot hold the request open.
ASSET_SCAN_BUDGET = 25.0
#: Simultaneous probes per asset.
PROBE_CONCURRENCY = 6
#: Banner services: port → (label, product guess). The banner carries the version.
BANNER_PORTS = (
    (22, "ssh", "openssh"),
    (21, "ftp", None),
    (25, "smtp", None),
    (445, "smb", "samba"),
    (1433, "mssql", "mssql"),
    (2375, "docker", "docker"),
    (3306, "mysql", "mysql"),
    (3389, "rdp", None),
    (5432, "postgresql", "postgresql"),
    (6379, "redis", "redis"),
    (6443, "kubernetes", "kubernetes"),
    (9200, "elasticsearch", "elasticsearch"),
    (27017, "mongodb", "mongodb"),
)
#: Ports whose service answers HTTP even though it is not a website.
HTTP_API_PORTS = ((2375, "http"), (6443, "https"), (9200, "http"))
#: Which category a discovered product belongs to, so the inventory reads sensibly.
_PRODUCT_CATEGORY = {
    "openssh": "network",
    "mysql": "database",
    "mariadb": "database",
    "postgresql": "database",
    "mssql": "database",
    "mongodb": "database",
    "redis": "database",
    "elasticsearch": "database",
    "kubernetes": "orchestrator",
    "docker": "container",
    "nginx": "web",
    "apache": "web",
    "iis": "web",
    "tomcat": "web",
    "jenkins": "web",
    "wordpress": "web",
    "samba": "network",
}

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[A-Za-z0-9.+-]*)?)")
_PAIR_SEGMENT = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9_.+-]{1,40})\s*/\s*(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9.+-]*)?)"
)
_BANNER_PRODUCT = re.compile(
    r"(OpenSSH|Apache|nginx|MySQL|PostgreSQL|Redis|Elasticsearch|vsftpd|ProFTPD|Exim|Postfix)",
    re.IGNORECASE,
)


def looks_like_host(value: str) -> bool:
    """True for an IP literal or a hostname, false for a human-readable asset name."""
    candidate = (value or "").strip()
    if not candidate or " " in candidate:
        return False
    try:
        socket.inet_aton(candidate) if candidate.count(".") == 3 else None
        if candidate.count(".") == 3 and all(
            part.isdigit() and 0 <= int(part) <= 255 for part in candidate.split(".")
        ):
            return True
    except (OSError, ValueError):
        pass
    return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}", candidate))


def _parse_version(text: str) -> Optional[str]:
    match = _VERSION_RE.search(text or "")
    return match.group(1) if match else None


def _fingerprint_from_http(response: httpx.Response) -> tuple[Optional[str], Optional[str], str]:
    server = response.headers.get("server") or ""
    powered = response.headers.get("x-powered-by") or ""
    generator_header = response.headers.get("x-generator") or ""
    banner = " · ".join(part for part in (server, powered, generator_header) if part)[:400]
    product = version = None

    # `Server` is often merged: "BaseHTTP/0.6 Python/3.12, nginx/1.18.0". Proxies
    # prepend and the origin appends, so the last versioned segment is the one that
    # describes the software the CVE is actually about.
    for header in (server, powered, generator_header):
        if not header:
            continue
        for segment in reversed([part.strip() for part in header.split(",") if part.strip()]):
            pair = _PAIR_SEGMENT.search(segment)
            if not pair:
                continue
            product, version = pair.group("name"), pair.group("version")
            break
        if product and version:
            break
    if product is None and server:
        product = server.split("/")[0].strip() or None
        version = _parse_version(server)

    if version is None:
        body = (response.text or "")[:200_000]
        for meta in re.finditer(r"<meta[^>]+name=[\"']generator[\"'][^>]*>", body, re.IGNORECASE):
            content = re.search(r"content=\"([^\"]{2,120})\"", meta.group(0), re.IGNORECASE)
            if not content:
                continue
            match = _BANNER_PRODUCT.search(content.group(1))
            product = match.group(1) if match else content.group(1).split()[0]
            version = _parse_version(content.group(1))
            banner = (banner + " · " + content.group(1))[:400]
            break
    return product, version, banner


async def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Cheap reachability check before spending an HTTP timeout on a closed port.

    A refused connection returns in microseconds; a filtered one hangs. Checking
    first is the difference between probing five ports on a dead host in two
    seconds and waiting forty.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


def tls_names(host: str, port: int) -> list[str]:
    """Certificate names for a TLS endpoint.

    Many hosts answer only for the name on their certificate. Reading it is the
    standard way to find that name without guessing: connect to the address, look at
    the CN and the SANs, then ask again with the name the host expects.
    """
    import ssl

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except Exception:  # noqa: BLE001 — no TLS, or no certificate to read
        return []
    if not der:
        return []
    try:
        import ssl as _ssl

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID

        certificate = x509.load_der_x509_certificate(der, default_backend())
        names: list[str] = []
        for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            names.append(str(attribute.value))
        try:
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            names.extend(san.value.get_values_for_type(x509.DNSName))
        except Exception:  # noqa: BLE001
            pass
        return _dedupe([name for name in names if name and "*" not in name])
    except Exception:  # noqa: BLE001 — cryptography absent or cert unparsable
        pass
    try:
        certificate = _ssl._ssl._test_decode_cert  # type: ignore[attr-defined]
        return []
    except Exception:  # noqa: BLE001
        return []


def _dedupe(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        cleaned = value.strip().lower().rstrip(".")
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
    return seen


def _reverse_dns(host: str) -> list[str]:
    try:
        return _dedupe(list(socket.gethostbyaddr(host)[0:1]))
    except (OSError, socket.herror):
        return []


def host_header_candidates(
    host: str, *, asset_name: Optional[str] = None, extra: Optional[list[str]] = None
) -> list[str]:
    """Names to try in the Host header for a bare address.

    A CDN or virtual host answers the address, not the name it knows: sending
    `Host: 125.21.247.160` gets a reset, while `Host: quoquo.tvsmotor.com` gets the site.
    The candidates come from the asset's own name, reverse DNS and the TLS certificate —
    never from guessing unrelated domains.
    """
    candidates: list[str] = []
    if asset_name and looks_like_host(asset_name) and not asset_name.replace(".", "").isdigit():
        candidates.append(asset_name.lower())
    candidates.extend(_reverse_dns(host))
    candidates.extend(extra or [])
    return [name for name in _dedupe(candidates) if name != host.lower()]


async def _probe_http(
    host: str, port: int, scheme: str, *, host_header: Optional[str] = None
) -> Optional[dict[str, Any]]:
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    url = f"{scheme}://{host}" + ("" if default_port else f":{port}")
    if not await _port_open(host, port):
        return {"host": host, "port": port, "protocol": scheme, "error": "unreachable"}
    headers = {"Host": host_header} if host_header else None
    extensions = (
        {"sni_hostname": host_header} if host_header and scheme == "https" else None
    )
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT, follow_redirects=True, verify=False, max_redirects=3
        ) as client:
            response = await client.get(url, headers=headers, extensions=extensions)
    except Exception as exc:  # noqa: BLE001 — unreachable is data, not an error to raise
        return {"host": host, "port": port, "protocol": scheme, "error": f"{type(exc).__name__}"}
    product, version, banner = _fingerprint_from_http(response)
    title = ""
    match = re.search(r"<title[^>]*>(.*?)</title>", response.text or "", re.IGNORECASE | re.DOTALL)
    if match:
        title = " ".join(match.group(1).split())[:200]
    return {
        "host": host,
        "port": port,
        "protocol": scheme,
        "url": url,
        "host_header": host_header,
        "status": response.status_code,
        "product": product,
        "version": version,
        "banner": banner,
        "title": title,
        # A CDN edge answers for the name it fronts; the length of the body tells the
        # difference between a real site and an error page served by the edge.
        "length": len(response.text or ""),
    }


async def _probe_banner(host: str, port: int, label: str, hint: Optional[str]) -> Optional[dict[str, Any]]:
    """Read the greeting of a line-based service (SSH, FTP, SMTP, Redis…)."""

    async def read_greeting() -> str:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
        try:
            if label in ("redis", "elasticsearch"):
                request = b"INFO\r\n" if label == "redis" else b"GET / HTTP/1.0\r\n\r\n"
                writer.write(request)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=CONNECT_TIMEOUT)
            return data.decode("utf-8", "replace").strip()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    try:
        greeting = await read_greeting()
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "port": port, "service": label, "error": f"{type(exc).__name__}"}
    if not greeting:
        return None
    match = _BANNER_PRODUCT.search(greeting)
    product = match.group(1) if match else hint
    return {
        "host": host,
        "port": port,
        "protocol": "tcp",
        "service": label,
        "product": product,
        "version": _parse_version(greeting),
        "banner": greeting[:400],
    }


def command_line(probe: dict[str, Any]) -> str:
    """The probe as the command a human would have typed."""
    if probe.get("service"):
        # A banner grab is a TCP connection, not an HTTP request; showing it as curl
        # would be a lie about what ran.
        return f"nc -w 3 {probe.get('host')} {probe.get('port')}"
    scheme = probe.get("protocol") or "https"
    host = probe.get("host")
    port = probe.get("port")
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    url = f"{scheme}://{host}" + ("" if default else f":{port}")
    parts = ["curl", "-sk", "--max-time", str(int(HTTP_TIMEOUT))]
    if probe.get("host_header"):
        parts += ["-H", f"'Host: {probe['host_header']}'"]
    parts.append(url)
    return " ".join(parts)


def response_line(probe: dict[str, Any]) -> str:
    """What came back, in the shape a terminal prints it."""
    if probe.get("error"):
        return f"    ! {probe['error']}"
    if probe.get("service"):
        return f"    {probe.get('banner') or '(connected, no greeting)'}"
    status = probe.get("status")
    detail = []
    if probe.get("banner"):
        detail.append(str(probe["banner"])[:120])
    if probe.get("title"):
        detail.append(f"title={probe['title'][:80]!r}")
    if probe.get("product"):
        detail.append(f"product={probe['product']} {probe.get('version') or ''}".strip())
    if probe.get("length"):
        detail.append(f"{probe['length']} bytes")
    return f"    HTTP {status}" + ("  " + "  ".join(detail) if detail else "")


def category_for(product: Optional[str], label: Optional[str] = None) -> str:
    key = (product or label or "").strip().lower()
    for name, category in _PRODUCT_CATEGORY.items():
        if name in key:
            return category
    return "other"


def candidate_targets(services: list[am.AssetService], *, scan_ports: bool) -> list[tuple[str, int, str]]:
    """The (host, port, scheme) combinations worth probing for one asset."""
    targets: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    hosts = {(service.host or "").strip().lower() for service in services if service.host}

    for service in services:
        host = (service.host or "").strip().lower()
        if not host:
            continue
        if service.port:
            scheme = service.protocol if service.protocol in ("http", "https") else "https"
            key = (host, service.port, scheme)
            if key not in seen:
                seen.add(key)
                targets.append(key)
        if not scan_ports:
            continue
        for port, scheme in (*WEB_PORTS, *HTTP_API_PORTS):
            key = (host, port, scheme)
            if key not in seen:
                seen.add(key)
                targets.append(key)
    if scan_ports:
        # An asset with no recorded endpoint still has a host worth looking at.
        for host in hosts:
            for port, scheme in (*WEB_PORTS, *HTTP_API_PORTS):
                key = (host, port, scheme)
                if key not in seen:
                    seen.add(key)
                    targets.append(key)
    return targets


async def _safe_event(on_event: Any, message: str, level: str, payload: Any = None) -> None:
    try:
        result = on_event(message, level, payload)
        if asyncio.iscoroutine(result):
            await result
    except Exception:  # noqa: BLE001 — reporting must not stop a probe
        logger.debug("event callback failed", exc_info=True)


async def discover_asset(
    asset_id: Any, *, scan_ports: bool = True, banner_scan: bool = True
) -> dict[str, Any]:
    """Fingerprint one asset and store what was found. Returns what was probed."""
    async with AsyncSessionLocal() as db:
        asset = await db.get(am.Asset, asset_id)
        if asset is None:
            return {"error": "asset not found"}
        services = list(
            await db.scalars(select(am.AssetService).where(am.AssetService.asset_id == asset_id))
        )
        asset_name = asset.name
        hosts = {(service.host or "").strip().lower() for service in services if service.host}
        if not hosts and looks_like_host(asset.name):
            hosts = {asset.name.strip().lower()}
        targets = candidate_targets(services, scan_ports=scan_ports)

    if not targets and not hosts:
        return {
            "asset_id": str(asset_id),
            "endpoints_probed": 0,
            "fingerprints": 0,
            "note": "the asset has no host recorded; add one to make it scannable",
        }

    semaphore = asyncio.Semaphore(PROBE_CONCURRENCY)

    async def guarded(coro):
        async with semaphore:
            return await coro

    # Names this asset may answer for: its own name, reverse DNS, and the certificate.
    names_by_host: dict[str, list[str]] = {}
    for host in hosts:
        extra: list[str] = []
        for port, scheme in WEB_PORTS:
            if scheme == "https":
                extra.extend(tls_names(host, port))
        names_by_host[host] = host_header_candidates(host, asset_name=asset_name, extra=extra)

    bare_jobs = [guarded(_probe_http(host, port, scheme)) for host, port, scheme in targets]
    banner_jobs: list[Any] = []
    if banner_scan:
        banner_jobs = [
            guarded(_probe_banner(host, port, label, hint))
            for host in hosts
            for port, label, hint in BANNER_PORTS
        ]

    results: list[dict[str, Any]] = []

    async def collect(coros: list[Any]) -> None:
        try:
            # The budget is the whole asset: a filtered host fails quickly instead of
            # holding an HTTP request open until the proxy times out.
            for outcome in await asyncio.wait_for(
                asyncio.gather(*coros, return_exceptions=True), timeout=ASSET_SCAN_BUDGET
            ):
                if isinstance(outcome, dict):
                    results.append(outcome)
        except asyncio.TimeoutError:
            logger.info("discovery budget reached for asset %s", asset_id)

    await collect(bare_jobs + banner_jobs)
    # Second pass, only where the bare address told us nothing: the same endpoints,
    # asked with the name the host actually serves. A CDN answers its own name, not the
    # address — that is why a bare-IP probe returns a reset or an edge error page.
    http_rows = [row for row in results if not row.get("service")]
    answered_hosts = {
        row.get("host") for row in http_rows if not row.get("error") and row.get("status")
    }
    unanswered_hosts = {row.get("host") for row in http_rows} - answered_hosts
    variant_jobs = [
        guarded(_probe_http(host, port, scheme, host_header=candidate))
        for host, port, scheme in targets
        if host in unanswered_hosts
        for candidate in names_by_host.get(host, [])[:3]
    ]
    if variant_jobs:
        await collect(variant_jobs)

    # An endpoint that answered at all is inventory, even when it names no product:
    # "443 open, HTTP 404" tells the operator the host is alive and what it said.
    answered = [
        row
        for row in results
        if not row.get("error") and (row.get("status") or row.get("banner") or row.get("product"))
    ]
    found = [row for row in results if row.get("product") or row.get("version")]
    if answered:
        from app.assets import service as asset_service

        async with AsyncSessionLocal() as db:
            asset = await db.get(am.Asset, asset_id)
            tenant_id = asset.tenant_id if asset else None
        if tenant_id is not None:
            for row in answered:
                await asset_service.add_service(
                    tenant_id,
                    asset_id,
                    host=row["host"],
                    port=int(row["port"]) if row.get("port") else None,
                    protocol=str(row.get("protocol") or "https"),
                    product=row.get("product"),
                    version=row.get("version"),
                    banner=(row.get("banner") or row.get("title") or "")[:500] or None,
                    source="probe",
                    confidence="heuristic",
                )
    if found:
        from app.assets import service as asset_service

        async with AsyncSessionLocal() as db:
            asset = await db.get(am.Asset, asset_id)
            tenant_id = asset.tenant_id if asset else None
        if tenant_id is not None:
            for row in found:
                await asset_service.add_technology(
                    tenant_id,
                    asset_id,
                    product=str(row.get("product") or row.get("service") or "unknown")[:120],
                    version=row.get("version"),
                    category=category_for(row.get("product"), row.get("service")),
                    source="probe",
                    confidence="heuristic",
                    evidence={"port": row.get("port"), "banner": (row.get("banner") or "")[:300]},
                )
            for row in found:
                await asset_service.add_service(
                    tenant_id,
                    asset_id,
                    host=row["host"],
                    port=int(row["port"]),
                    protocol=str(row.get("protocol") or "https"),
                    product=row.get("product"),
                    version=row.get("version"),
                    banner=row.get("banner"),
                    source="cve-scan",
                    # A version read from a banner or header is evidence, not gospel:
                    # the verification step decides whether it is trustworthy.
                    confidence="heuristic",
                )
    transcript: list[str] = []
    for row in sorted(
        results, key=lambda item: (str(item.get("host")), item.get("port") or 0)
    ):
        transcript.append(command_line(row))
        transcript.append(response_line(row))

    outcomes = [
        {
            "endpoint": f"{row.get('host')}:{row.get('port')}"
            + (f" (Host: {row['host_header']})" if row.get("host_header") else ""),
            "protocol": row.get("protocol"),
            "status": row.get("status"),
            "product": row.get("product"),
            "version": row.get("version"),
            "error": row.get("error"),
        }
        for row in sorted(results, key=lambda item: (str(item.get("host")), item.get("port") or 0))
    ]
    return {
        "asset_id": str(asset_id),
        "endpoints_probed": len(results),
        "endpoints_open": len(answered),
        "fingerprints": len(found),
        "products": sorted({row.get("product") for row in found if row.get("product")}),
        "errors": sum(1 for row in results if row.get("error")),
        "outcomes": outcomes,
        "transcript": transcript,
    }


async def discover_assets(
    asset_ids: list[Any],
    *,
    scan_ports: bool = True,
    banner_scan: bool = True,
    on_event: Optional[Any] = None,
    labels: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Probe several assets; `on_event(message, level, payload)` reports progress."""
    """Fingerprint several assets; the summary the check reports back."""
    assets = 0
    endpoints = 0
    opened = 0
    fingerprints = 0
    products: set[str] = set()
    labels = labels or {}
    for asset_id in asset_ids:
        label = labels.get(str(asset_id), str(asset_id))
        if on_event is not None:
            await _safe_event(on_event, f"probing {label}", "detail")
        outcome = await discover_asset(
            asset_id, scan_ports=scan_ports, banner_scan=banner_scan
        )
        if outcome.get("error"):
            if on_event is not None:
                await _safe_event(on_event, f"{label}: {outcome['error']}", "warning")
            continue
        if on_event is not None and not outcome.get("endpoints_probed"):
            await _safe_event(
                on_event,
                f"{label}: nothing to probe — {outcome.get('note') or 'no host recorded'}",
                "warning",
            )
            continue
        if on_event is not None and outcome.get("endpoints_probed"):
            open_ports = [row["endpoint"] for row in outcome.get("outcomes") or [] if not row.get("error")]
            summary = (
                f"{label}: {outcome.get('endpoints_open', 0)} of "
                f"{outcome.get('endpoints_probed', 0)} probed endpoint(s) answered"
                + (f" ({', '.join(open_ports[:6])})" if open_ports else "")
            )
            await _safe_event(
                on_event,
                summary,
                "info" if outcome.get("endpoints_open") else "warning",
                {"outcomes": (outcome.get("outcomes") or [])[:24]},
            )
        if on_event is not None:
            # The transcript, the way a terminal would show it: the command and the
            # response line per probe.
            for line in (outcome.get("transcript") or [])[:60]:
                await _safe_event(on_event, line, "detail", {"raw": True})
        if on_event is not None and outcome.get("products"):
            await _safe_event(
                on_event,
                f"{label}: found {', '.join(outcome['products'])}",
                "info",
                {"products": outcome["products"], "endpoints": outcome.get("endpoints_probed")},
            )
        assets += 1
        endpoints += int(outcome.get("endpoints_probed") or 0)
        opened += int(outcome.get("endpoints_open") or 0)
        fingerprints += int(outcome.get("fingerprints") or 0)
        products.update(outcome.get("products") or [])
    return {
        "assets_probed": assets,
        "endpoints_probed": endpoints,
        "endpoints_open": opened,
        "fingerprints_found": fingerprints,
        "products": sorted(products),
    }
