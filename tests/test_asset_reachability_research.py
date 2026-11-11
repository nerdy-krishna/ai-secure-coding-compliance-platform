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
        return port == 443

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_tcp_open", opens)

    outcome = asyncio.run(reachability.check_host("example.com", [443, 80]))

    assert outcome["reachable"] is True
    assert outcome["port"] == 443
    assert outcome["reason"] is None


def test_dns_failure_is_named(monkeypatch):
    async def no_dns(host):
        return False, "dns_failed"

    monkeypatch.setattr(reachability, "_resolve", no_dns)

    outcome = asyncio.run(reachability.check_host("nope.invalid"))

    assert outcome["reachable"] is False
    assert outcome["reason"] == "dns_failed"


def test_no_open_port_is_unreachable_not_unknown(monkeypatch):
    async def resolves(host):
        return True, None

    async def closed(host, port):
        return False

    monkeypatch.setattr(reachability, "_resolve", resolves)
    monkeypatch.setattr(reachability, "_tcp_open", closed)

    outcome = asyncio.run(reachability.check_host("10.0.0.9", [443]))

    assert outcome["reachable"] is False
    assert outcome["reason"] == "no_open_port"


def test_the_engine_probe_asks_reachability_before_scanning():
    """The whole point: a dead host must not consume nmap/whatweb/nuclei time."""
    source = inspect.getsource(inventory_probe.run_job)

    assert "reachability.check_host" in source
    assert "unreachable" in source
    assert source.index("check_host") < source.index("_run_nmap"), (
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
