"""Reachability first, research before testing.

Two behaviours that decide whether inventory work is worth the operator's time: a host that
will not answer is recorded and skipped rather than scanned for minutes, and a CVE is
explained before anything is sent to an asset.
"""

from __future__ import annotations

import asyncio
import inspect

from app.assets import cve_workflow, reachability
from app.pentest import inventory_probe


def test_a_host_that_resolves_and_answers_is_reachable(monkeypatch):
    async def resolves(host):
        return True, None

    async def opens(host, port):
        return reachability.OPEN if port == 443 else reachability.FILTERED

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_connect", opens)

    outcome = asyncio.run(reachability.check_host("example.com", [443, 80]))

    assert outcome["reachable"] is True
    assert outcome["state"] == reachability.UP
    assert outcome["port"] == 443
    assert outcome["reason"] is None


def test_dns_failure_is_named(monkeypatch):
    async def no_dns(host):
        return False, "dns_failed"

    monkeypatch.setattr(reachability, "_resolve", no_dns)

    outcome = asyncio.run(reachability.check_host("nope.invalid"))

    assert outcome["reachable"] is False
    assert outcome["reason"] == "dns_failed"


def test_no_open_port_is_filtered_rather_than_declared_absent(monkeypatch):
    """Silence is not absence: a firewall that drops packets looks like an empty address."""

    async def resolves(host):
        return True, None

    async def drops(host, port):
        return reachability.FILTERED

    async def nmap(host, udp=False):
        return {"alive": None, "mechanism": "host seems down", "seconds": 3.0}

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_connect", drops)
    monkeypatch.setattr(reachability, "_nmap", nmap)

    outcome = asyncio.run(reachability.check_host("10.0.0.9", [443]))

    assert outcome["reachable"] is False
    assert outcome["state"] == reachability.UNKNOWN
    assert outcome["reason"] == "filtered"


def test_the_engine_probe_asks_reachability_before_scanning():
    """The whole point: a dead host must not consume nmap/whatweb/nuclei time."""
    source = inspect.getsource(inventory_probe.run_job)

    assert "reachability.check_asset" in source
    assert "SCAN_SKIP" in source
    assert source.index("check_asset") < source.index("_run_nmap"), (
        "reachability must be decided before the first scanner runs"
    )


def test_research_reports_a_model_failure_instead_of_dressing_it_up():
    source = inspect.getsource(cve_workflow.research_cve)

    assert "_looks_like_error" in source
    assert "research_error" in source


def test_browse_filters_are_applied_to_the_query():
    source = inspect.getsource(cve_workflow.browse)

    assert "ilike" in source, "search matches id or description"
    assert "kev.is_(True)" in source
    assert "severity ==" in source
