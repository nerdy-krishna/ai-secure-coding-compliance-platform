"""The reachability ladder.

The bug that started this: a live Postgres host with only 5432 open was reported
"unreachable (no_open_port)" and skipped, because the check asked "is 443, 80 or 22 open"
instead of "is the host there". Every test here pins one part of the repair.
"""

from __future__ import annotations

import asyncio
import inspect

from app.assets import reachability


def test_a_refused_connection_proves_the_host_is_alive(monkeypatch):
    """The managed-SQL case: nothing listens on 443, but the host answers with a RST."""

    async def resolves(host):
        return True, None

    async def connect(host, port):
        return reachability.REFUSED if port == 5432 else reachability.FILTERED

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_connect", connect)

    outcome = asyncio.run(
        reachability.check_host("sql.internal", [5432, 443], kind="database", max_level=2)
    )

    assert outcome["state"] == reachability.UP
    assert outcome["reachable"] is True
    assert outcome["port"] == 5432
    assert "refused" in outcome["evidence"]


def test_silence_is_filtered_not_down(monkeypatch):
    async def resolves(host):
        return True, None

    async def connect(host, port):
        return reachability.FILTERED

    async def nmap(host, udp=False):
        return {"alive": None, "mechanism": "host seems down", "seconds": 3.0}

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_connect", connect)
    monkeypatch.setattr(reachability, "_nmap", nmap)

    outcome = asyncio.run(reachability.check_host("10.0.0.1", [], kind="firewall"))

    assert outcome["state"] == reachability.UNKNOWN
    assert outcome["reason"] == "filtered"
    # Filtered must not be treated as absent: a hardened host is exactly what you scan.
    assert reachability.scan_policy(outcome) == reachability.SCAN_REDUCED


def test_no_route_is_proven_down(monkeypatch):
    async def resolves(host):
        return True, None

    async def connect(host, port):
        return reachability.UNREACHABLE

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_connect", connect)

    outcome = asyncio.run(reachability.check_host("192.0.2.9", [], max_level=2))

    assert outcome["state"] == reachability.DOWN
    assert outcome["reason"] == "no_route"
    assert reachability.scan_policy(outcome) == reachability.SCAN_SKIP


def test_dns_failure_is_down_without_probing_ports(monkeypatch):
    async def no_dns(host):
        return False, "dns_failed"

    async def connect(host, port):  # pragma: no cover — must not be reached
        raise AssertionError("no port probe after a DNS failure")

    monkeypatch.setattr(reachability, "_resolve", no_dns)
    monkeypatch.setattr(reachability, "_connect", connect)

    outcome = asyncio.run(reachability.check_host("nope.invalid"))

    assert outcome["state"] == reachability.DOWN
    assert outcome["reason"] == "dns_failed"
    assert outcome["level"] == 1


def test_the_ladder_climbs_to_nmap_only_when_ports_are_silent(monkeypatch):
    calls: list[int] = []
    # Levels 3 and 4 need nmap; the worker test image does not ship it.
    monkeypatch.setattr(reachability, "nmap_available", lambda: True)

    async def resolves(host):
        return True, None

    async def connect(host, port):
        calls.append(port)
        return reachability.FILTERED

    async def nmap(host, udp=False):
        return {"alive": True, "mechanism": "arp-response", "seconds": 0.1}

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_connect", connect)
    monkeypatch.setattr(reachability, "_nmap", nmap)

    outcome = asyncio.run(reachability.check_host("appliance.lan", [], kind="network"))

    assert outcome["state"] == reachability.UP
    assert outcome["level"] == 3
    assert "arp-response" in outcome["evidence"]
    # Level 2 tried a real port list — the kind profile plus the nmap top-20 — not the
    # old hardcoded three.
    assert {8443, 3306, 3389, 8080} <= set(calls)


def test_a_known_port_answers_at_level_one(monkeypatch):
    async def resolves(host):
        return True, None

    async def connect(host, port):
        return reachability.OPEN

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_connect", connect)

    outcome = asyncio.run(reachability.check_host("app.example.com", [8443]))

    assert outcome["state"] == reachability.UP
    assert outcome["level"] == 1
    assert outcome["port"] == 8443


def test_nmap_reason_is_parsed_not_guessed():
    assert reachability.parse_nmap_discovery(
        "Host is up, received conn-refused (0.00014s latency)."
    ) == {"alive": True, "mechanism": "conn-refused"}
    assert reachability.parse_nmap_discovery("Host is up.")["alive"] is True
    assert reachability.parse_nmap_discovery("Note: Host seems down.")["alive"] is False
    assert reachability.parse_nmap_discovery("garbage")["alive"] is None


def test_kind_profiles_include_the_non_web_ports():
    assert 5432 in reachability.KIND_PORTS["database"]
    assert 1433 in reachability.KIND_PORTS["database"]
    assert 22 in reachability.KIND_PORTS["firewall"]
    assert 6443 in reachability.KIND_PORTS["k8s"]
    # A host of unknown kind still gets the nmap top-20 as a tail.
    assert 3306 in reachability.TOP_PORTS


def test_the_probe_paths_ask_the_ladder_before_scanning():
    from app.assets import discovery
    from app.pentest import inventory_probe

    for source in (inspect.getsource(inventory_probe.run_job), inspect.getsource(discovery.discover_asset)):
        assert "check_asset" in source or "check_host" in source
        assert "scan_policy" in source, "every probe path must apply the same policy"
        assert "SCAN_SKIP" in source, "a proven-absent host must skip the scanners"
