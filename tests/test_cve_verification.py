"""LLM CVE verification: the model designs a check, the envelope runs it, evidence decides.

The safety envelope is the point of these tests. A model that proposes a POST, or a
URL on a host that is not the asset's, must not reach the network at all — and a
verdict of "applicable" with no deciding observation must be downgraded, because an
unearned verdict is worse than an honest "cannot tell".
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.assets import models as am
from app.assets import verification
from app.assets.verification import DetectionPlan, ProbeCheck, VerdictDecision


class FakeResponse:
    def __init__(self, status: int, body: str = "", headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self.text = body
        self.headers = headers or {}


class FakeClient:
    """Stands in for httpx.AsyncClient; records what was actually requested."""

    def __init__(self, responses: dict[str, FakeResponse] | None = None) -> None:
        self.responses = responses or {}
        self.requests: list[tuple[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def request(self, method: str, url: str):
        self.requests.append((method, url))
        return self.responses.get(url, FakeResponse(404, "not found"))


def services(host: str = "app.example.com") -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            host=host,
            port=443,
            protocol="https",
            path=None,
            product="nginx",
            version="1.18.0",
            banner="nginx/1.18.0",
            source="recon",
            confidence="heuristic",
        )
    ]


def plan(*checks: ProbeCheck, non_destructive: bool = True) -> DetectionPlan:
    return DetectionPlan(reasoning="probe the version endpoint", non_destructive=non_destructive, checks=list(checks))


def test_read_only_plan_runs(monkeypatch):
    client = FakeClient({"https://app.example.com/version": FakeResponse(200, "1.18.0")})
    monkeypatch.setattr(verification.httpx, "AsyncClient", lambda **kwargs: client)

    observations = asyncio.run(
        verification.run_plan(
            plan(
                ProbeCheck(
                    method="GET",
                    url="https://app.example.com/version",
                    rationale="nginx exposes its build here",
                    decides="the body shows 1.18.0, inside the affected range",
                )
            ),
            services=services(),
        )
    )

    assert client.requests == [("GET", "https://app.example.com/version")]
    assert observations[0]["status"] == 200
    assert "1.18.0" in observations[0]["body"]


def test_a_state_changing_plan_never_reaches_the_network(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(verification.httpx, "AsyncClient", lambda **kwargs: client)

    observations = asyncio.run(
        verification.run_plan(
            plan(
                ProbeCheck(
                    method="GET",
                    url="https://app.example.com/x",
                    rationale="r",
                    decides="d",
                ),
                non_destructive=False,
            ),
            services=services(),
        )
    )

    assert client.requests == []
    assert "not marked non-destructive" in observations[0]["error"]


def test_check_on_a_foreign_host_is_refused(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(verification.httpx, "AsyncClient", lambda **kwargs: client)

    observations = asyncio.run(
        verification.run_plan(
            plan(
                ProbeCheck(
                    method="GET",
                    url="https://evil.example.net/version",
                    rationale="r",
                    decides="d",
                )
            ),
            services=services(),
        )
    )

    assert client.requests == []
    assert "not one of the asset's hosts" in observations[0]["error"]


def test_unsafe_method_is_refused_even_if_the_schema_were_bypassed(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(verification.httpx, "AsyncClient", lambda **kwargs: client)
    check = ProbeCheck(
        method="GET", url="https://app.example.com/x", rationale="r", decides="d"
    )
    check = check.model_copy(update={"method": "POST"})  # simulate a tampered plan

    observations = asyncio.run(
        verification.run_plan(plan(check), services=services())
    )

    assert client.requests == []
    assert "refused method POST" in observations[0]["error"]


def test_applicable_without_a_deciding_check_is_downgraded():
    decision = VerdictDecision(
        verdict="applicable", confidence="high", reason="looks vulnerable", deciding_check=None
    )
    observations = [{"n": 1, "url": "https://app.example.com/version", "status": 200, "body": "1.18.0"}]

    enforced = verification._enforce_evidence(decision, observations)

    assert enforced.verdict == am.UNDETERMINED
    assert "downgraded" in enforced.reason


def test_applicable_standing_on_a_failed_check_is_downgraded():
    decision = VerdictDecision(
        verdict="applicable", confidence="high", reason="confirmed", deciding_check=2
    )
    observations = [{"n": 2, "url": "https://app.example.com/x", "error": "ConnectError"}]

    enforced = verification._enforce_evidence(decision, observations)

    assert enforced.verdict == am.UNDETERMINED


def test_applicable_with_a_real_observation_stands():
    decision = VerdictDecision(
        verdict="applicable", confidence="high", reason="version 1.18.0 confirmed", deciding_check=1
    )
    observations = [{"n": 1, "url": "https://app.example.com/version", "status": 200, "body": "1.18.0"}]

    enforced = verification._enforce_evidence(decision, observations)

    assert enforced.verdict == am.APPLICABLE
    assert enforced.confidence == "high"


def test_plan_is_capped_at_the_envelope_size(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(verification.httpx, "AsyncClient", lambda **kwargs: client)
    checks = [
        ProbeCheck(
            method="GET",
            url=f"https://app.example.com/v{index}",
            rationale="r",
            decides="d",
        )
        for index in range(10)
    ]

    asyncio.run(verification.run_plan(plan(*checks), services=services()))

    assert len(client.requests) == verification.MAX_CHECKS
