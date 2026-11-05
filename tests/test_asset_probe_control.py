"""Controlling an inventory probe: how long its stages take, and how it stops.

Probing felt stuck because each asset ran a 1000-port version scan, an aggressive whatweb
crawl and a full nuclei sweep, one job at a time. The stages are now sized for inventory —
identify the asset, do not assess it — and a probe can be stopped.
"""

from __future__ import annotations

import asyncio
import inspect

from app.pentest import inventory_probe


def capture(monkeypatch) -> list[list[str]]:
    calls: list[list[str]] = []

    async def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return 0, "", ""

    monkeypatch.setattr(inventory_probe, "run_subprocess", fake_run)
    return calls


def test_nmap_is_fast_by_default(monkeypatch):
    calls = capture(monkeypatch)

    asyncio.run(inventory_probe._run_nmap("10.0.0.5", None))

    command = calls[0]
    assert "-F" in command, "the top 100 ports answer 'what is listening'"
    assert "--version-light" in command
    assert "--top-ports" not in command, "1000 ports is an assessment, not inventory"


def test_an_explicit_port_list_is_honoured(monkeypatch):
    calls = capture(monkeypatch)

    asyncio.run(inventory_probe._run_nmap("10.0.0.5", "22,80,443"))

    command = calls[0]
    assert "-p" in command and "22,80,443" in command
    assert "-F" not in command


def test_whatweb_does_not_crawl(monkeypatch):
    calls = capture(monkeypatch)

    asyncio.run(inventory_probe._run_whatweb("10.0.0.5", "https"))

    command = calls[0]
    assert command[command.index("-a") + 1] == "1", "aggression 3 crawls and brute-forces paths"


def test_nuclei_is_rate_limited(monkeypatch):
    calls = capture(monkeypatch)

    asyncio.run(inventory_probe._run_nuclei("10.0.0.5", "https"))

    assert "-rate-limit" in calls[0]


def test_nuclei_is_opt_in_per_job():
    """It is the slow stage; the caller decides whether it runs."""
    source = inspect.getsource(inventory_probe.run_job)

    assert '"nuclei" in tools' in source
    assert "nuclei: skipped" in source


def test_a_cancelled_job_is_never_claimed():
    """A stop request must not leave work that the engine picks up next tick."""
    source = inspect.getsource(inventory_probe.tick)

    assert "cancel_requested.is_(False)" in source


def test_each_stage_reports_its_duration():
    source = inspect.getsource(inventory_probe.run_job)

    assert "nmap_seconds" in source and "whatweb_seconds" in source
