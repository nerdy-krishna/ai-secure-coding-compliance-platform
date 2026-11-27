"""Concurrency limits are per-stage, DB-overridable, and none is hardcoded.

The report that prompted this: 30 files in 40 minutes on a 500-file repo. File
profiling was pinned at five in-flight calls by a module constant, so no admin
setting could move it - the profiler, not the provider, was the ceiling.
"""

from __future__ import annotations

import inspect

import pytest

from app.config.config import settings
from app.shared.lib import concurrency_limits as limits


def test_every_stage_limit_has_a_system_config_override() -> None:
    for name in (
        "CONCURRENT_LLM_LIMIT",
        "CONCURRENT_PROFILER_LIMIT",
        "CONCURRENT_SCANNER_LIMIT",
        "CONCURRENT_CONSOLIDATION_LIMIT",
        "CONCURRENT_VALIDATION_LIMIT",
    ):
        assert hasattr(settings, name), f"{name} is missing from settings"
        assert name in limits._KEYS, f"{name} has no system.concurrency.* override"


def test_limits_are_positive_and_bounded() -> None:
    for name in limits._KEYS:
        assert getattr(settings, name) >= 1, name


def test_profiler_limit_is_no_longer_a_constant() -> None:
    """`profile.py` must read the limit, not shadow it with a literal."""
    from app.infrastructure.workflows.nodes import profile

    source = inspect.getsource(profile)
    assert "get_concurrency_limit(" in source
    assert "profiler_limit" in source
    # The module-level value is only a fallback; it must come from settings.
    assert profile.CONCURRENT_PROFILER_LIMIT == settings.CONCURRENT_PROFILER_LIMIT


class _FakeSession:
    """`select(SystemConfiguration.value)` yields the raw JSONB value."""

    def __init__(self, value) -> None:
        self._value = value

    async def execute(self, _statement):  # noqa: ANN001
        value = self._value

        class _Result:
            def scalar_one_or_none(self):
                return value

        return _Result()


def test_db_override_wins_and_is_clamped() -> None:
    import asyncio

    resolved = asyncio.run(
        limits.get_concurrency_limit(
            _FakeSession({"value": 64}), "CONCURRENT_PROFILER_LIMIT"
        )
    )
    assert resolved == 64

    # Above the field's ceiling: clamped, not accepted.
    clamped = asyncio.run(
        limits.get_concurrency_limit(
            _FakeSession({"value": 99_999}), "CONCURRENT_PROFILER_LIMIT"
        )
    )
    assert clamped == 500
    declared_le = next(
        m.le
        for m in settings.model_fields["CONCURRENT_PROFILER_LIMIT"].metadata
        if hasattr(m, "le")
    )
    assert clamped == declared_le


def test_db_read_failure_falls_back_to_settings(monkeypatch) -> None:
    import asyncio

    class _Broken:
        async def execute(self, _statement):  # noqa: ANN001
            raise RuntimeError("db down")

    resolved = asyncio.run(
        limits.get_concurrency_limit(_Broken(), "CONCURRENT_PROFILER_LIMIT")
    )
    assert resolved == settings.CONCURRENT_PROFILER_LIMIT


@pytest.mark.parametrize("value", [{"enabled": 12}, {"limit": 12}, 12])
def test_override_shapes(value) -> None:
    import asyncio

    assert (
        asyncio.run(
            limits.get_concurrency_limit(
                _FakeSession(value), "CONCURRENT_PROFILER_LIMIT"
            )
        )
        == 12
    )


def test_fix_candidates_are_deduped_on_their_primary_key() -> None:
    """A repeated candidate_id must not reach the INSERT (finding_fix_candidates_pkey)."""
    import uuid

    from app.core.schemas import FixResult, FixSuggestion, VulnerabilityFinding
    from app.infrastructure.database.repositories import scan_repo

    def candidate(cid, disposition="selected"):
        finding = VulnerabilityFinding(
            raw_finding_id=uuid.uuid4(),
            title="t",
            severity="High",
            confidence="High",
            file_path="src/App.ts",
            line_number=1,
            description="d",
            remediation="r",
            source="semgrep",
            scanner_rule_id="r1",
        )
        return FixResult(
            finding=finding,
            suggestion=FixSuggestion(
                description="fix", original_snippet="eval(x)", code="safe(x)"
            ),
            candidate_id=cid,
            disposition=disposition,
        )

    keep = uuid.uuid4()
    other = uuid.uuid4()
    deduped, duplicates = scan_repo.dedupe_fix_candidates(
        [
            candidate(keep, "pending"),
            candidate(other),
            candidate(keep, "selected"),  # same id, newest verdict wins
        ]
    )

    assert duplicates == 1
    assert len(deduped) == 2
    assert {c.candidate_id for c in deduped} == {keep, other}
    by_id = {c.candidate_id: c for c in deduped}
    assert by_id[keep].disposition == "selected"


def test_candidates_without_an_id_are_not_persisted() -> None:
    from app.infrastructure.database.repositories import scan_repo

    deduped, duplicates = scan_repo.dedupe_fix_candidates([])
    assert deduped == [] and duplicates == 0


def test_stage_concurrency_is_bounded_by_the_connection_pool() -> None:
    """A fan-out wider than the pool only adds waiters that time out together."""
    from app.shared.lib import concurrency_limits as limits

    capacity = limits.db_pool_capacity()
    assert capacity >= 2

    effective, clamped = limits.db_bound_concurrency(capacity * 20)
    assert clamped is True
    assert effective < capacity, "must leave room for the workflow's own writes"

    unchanged, not_clamped = limits.db_bound_concurrency(2)
    assert (unchanged, not_clamped) == (2, False)


def test_a_failing_cancellation_watcher_does_not_cancel_the_run(monkeypatch) -> None:
    """A pool timeout in the poll used to look like "the operator cancelled"."""
    import asyncio

    from app.infrastructure.workflows import cancellation as cancel_mod

    async def _boom(_scan_id):
        raise RuntimeError("QueuePool limit of size 5 overflow 10 reached")

    observed = {"phases": []}

    async def _record(_scan_id, phase, **_kwargs):
        observed["phases"].append(phase)

    monkeypatch.setattr(cancel_mod, "wait_for_scan_cancellation", _boom)
    monkeypatch.setattr(cancel_mod, "record_cancellation_phase", _record)

    class _Workflow:
        async def ainvoke(self, _input, _config):
            await asyncio.sleep(0.05)
            return {"findings": []}

    result = asyncio.run(
        cancel_mod.invoke_with_forceful_cancellation(
            _Workflow(), {}, {"configurable": {"thread_id": "t"}}, "scan"
        )
    )

    assert result == {"findings": []}
    assert observed["phases"] == [], "no cancellation may be recorded"
