"""Admin-managed runtime limits: resolution order, clamping, seeding, live apply.

Everything that gated scan speed lived in `.env`, so an operator needed a shell and
a restart to change a number. These limits now live in `system_config`, seeded at
their maximum on first boot; the live ones (provider rate limits) are republished to
the running limiter registry on every refresh.
"""

from __future__ import annotations

import asyncio

import pytest

from app.config.config import settings
from app.shared.lib import runtime_settings


class _FakeResult:
    def __init__(self, rows) -> None:
        self._rows = rows

    def all(self):
        return self._rows

    def scalars(self):
        rows = [row[0] if isinstance(row, tuple) else row for row in self._rows]

        class _S:
            def all(self_inner):
                return rows

        return _S()


class _FakeSession:
    def __init__(self, rows=None, existing_keys=()) -> None:
        self.rows = rows or []
        self.existing_keys = list(existing_keys)
        self.added: list[object] = []
        self.commits = 0

    async def execute(self, _statement):  # noqa: ANN001 - mirrors AsyncSession
        # Two call shapes: the refresh reads (key, value) pairs, the seeder reads keys.
        if self.rows and isinstance(self.rows[0], tuple):
            return _FakeResult(self.rows)
        return _FakeResult([(k,) for k in self.existing_keys])

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        pass

    async def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _clear_cache():
    runtime_settings._cache.clear()
    yield
    runtime_settings._cache.clear()


def test_every_managed_key_maps_to_a_real_setting() -> None:
    keys = list(runtime_settings.managed_keys())
    assert len(keys) == len(set(keys)), "duplicate system_config key"
    for spec in runtime_settings.SPECS:
        assert hasattr(settings, spec.name), spec.name
        assert spec.key.startswith("system."), spec.key
    # the knobs that gate scan speed
    for expected in (
        "system.concurrency.llm_limit",
        "system.concurrency.profiler_limit",
        "system.worker.analysis_slots",
        "system.worker.prefetch_count",
        "system.ratelimit.deepseek.rpm",
        "system.ratelimit.deepseek.tpm",
    ):
        assert expected in keys


def test_effective_falls_back_to_the_environment_value() -> None:
    assert (
        runtime_settings.effective("CONCURRENT_PROFILER_LIMIT")
        == settings.CONCURRENT_PROFILER_LIMIT
    )


def test_refresh_applies_and_clamps_overrides() -> None:
    db = _FakeSession(
        rows=[
            ("system.concurrency.llm_limit", {"value": 40}),
            ("system.concurrency.profiler_limit", {"value": 5_000_000}),  # over the cap
            ("system.worker.analysis_slots", {"value": 0}),  # under the floor
        ]
    )
    snapshot = asyncio.run(runtime_settings.refresh(db))

    assert runtime_settings.effective("CONCURRENT_LLM_LIMIT") == 40
    # clamped to the field ceiling, never accepted as-is
    assert runtime_settings.effective("CONCURRENT_PROFILER_LIMIT") == 500
    assert runtime_settings.effective("WORKER_ANALYSIS_SLOTS") == 1
    assert snapshot["CONCURRENT_LLM_LIMIT"] == 40


def test_junk_rows_are_ignored() -> None:
    db = _FakeSession(rows=[("system.concurrency.llm_limit", {"value": "fast"})])
    asyncio.run(runtime_settings.refresh(db))
    assert (
        runtime_settings.effective("CONCURRENT_LLM_LIMIT")
        == settings.CONCURRENT_LLM_LIMIT
    )


def test_seeding_fills_missing_keys_at_their_maximum() -> None:
    db = _FakeSession(existing_keys=["system.concurrency.llm_limit"])
    seeded = asyncio.run(runtime_settings.seed_missing_maximums(db))

    by_key = {row.key: row.value for row in db.added}  # type: ignore[attr-defined]
    assert "system.concurrency.llm_limit" not in by_key, "existing row must be kept"
    # Concurrency seeds at the top of its range *bounded by what the connection pool can serve*,
    # which depends on the deployment's pool size — so the invariant is the bound, not the
    # literal 500. Asserting 500 made this test pass only under one pool configuration.
    from app.shared.lib.concurrency_limits import db_bound_concurrency

    expected_profiler, _reason = db_bound_concurrency(500)
    assert by_key["system.concurrency.profiler_limit"] == {"value": expected_profiler}
    # Every `system.concurrency.*` key is bounded by the pool; only the bound is invariant.
    # Worker slots are not in that namespace, so they seed at their own maximum.
    assert by_key["system.concurrency.scanner_limit"] == {
        "value": db_bound_concurrency(50)[0]
    }
    assert by_key["system.worker.analysis_slots"] == {"value": 32}
    # integers seed at their maximum; booleans/enums at the configured value
    assert by_key["system.evidence.enabled"] == {
        "value": settings.EVIDENCE_STORE_ENABLED
    }
    assert by_key["system.scan.workflow_timeout_seconds"] == {"value": 172_800}
    assert len(seeded) == len(runtime_settings.SPECS) - 1
    assert db.commits == 1


def test_catalog_is_the_single_source_for_the_admin_ui() -> None:
    """Every spec comes from the catalog, and every catalog row is renderable."""
    from app.shared.lib.settings_catalog import BY_ENV, DESCRIPTORS, sections_payload

    for spec in runtime_settings.SPECS:
        assert spec.key in BY_ENV[spec.name].key
    for descriptor in DESCRIPTORS:
        assert descriptor.label, descriptor.key
        assert descriptor.description, descriptor.key
        assert descriptor.section, descriptor.key
        if descriptor.kind == "int":
            assert descriptor.minimum is not None and descriptor.maximum is not None
            assert descriptor.minimum < descriptor.maximum, descriptor.key
        if descriptor.kind == "enum":
            assert descriptor.choices, descriptor.key
        assert descriptor.applies in {
            "live",
            "next-scan",
            "worker-restart",
            "app-restart",
        }, descriptor.key

    sections = sections_payload()
    assert sections, "the UI would render nothing"
    rendered = [entry["key"] for section in sections for entry in section["settings"]]
    assert set(rendered) == {d.key for d in DESCRIPTORS}


def test_write_validation_rejects_out_of_range_and_bad_types() -> None:
    from app.shared.lib.runtime_settings import validate_write

    assert validate_write("system.concurrency.llm_limit", {"value": 200}) == 200
    for bad in (0, 501, "lots"):
        with pytest.raises(ValueError):
            validate_write("system.concurrency.llm_limit", bad)
    assert validate_write("system.worker.analysis_slots", {"value": 2}) == 2
    with pytest.raises(ValueError):
        validate_write("system.worker.analysis_slots", 33)
    assert validate_write("system.evidence.enabled", {"value": "true"}) is True
    with pytest.raises(ValueError):
        validate_write("system.pentest.unknown_cwe_ceiling", "catastrophic")


def test_overlay_applies_resolved_values_to_settings() -> None:
    """`apply_to_settings` is what makes a restart-scoped key effective."""
    original = settings.WORKER_ANALYSIS_SLOTS
    try:
        runtime_settings.apply_to_settings({"WORKER_ANALYSIS_SLOTS": 7})
        assert settings.WORKER_ANALYSIS_SLOTS == 7
    finally:
        # `Settings` is frozen; the overlay itself bypasses that on purpose.
        object.__setattr__(settings, "WORKER_ANALYSIS_SLOTS", original)


def test_a_refresh_repoints_a_live_provider_limiter() -> None:
    from app.infrastructure.llm_client_rate_limiter import (
        initialize_rate_limiters,
        provider_rate_limiters,
    )

    initialize_rate_limiters()
    limiter = provider_rate_limiters["deepseek"]
    db = _FakeSession(
        rows=[
            ("system.ratelimit.deepseek.rpm", {"value": 4321}),
            ("system.ratelimit.deepseek.tpm", {"value": 987654}),
        ]
    )
    asyncio.run(runtime_settings.refresh(db))

    assert limiter.rpm_limit == 4321
    assert limiter.tpm_limit == 987654
    # the registry was mutated, not replaced: callers hold this reference
    assert provider_rate_limiters["deepseek"] is limiter


def test_repository_mapping_skips_oversized_and_minified_files() -> None:
    """Mapping must not stall on a generated bundle, and must say why it skipped."""
    pytest.importorskip(
        "tree_sitter",
        reason="AST mapping is worker-image only; run the suite in Docker",
    )
    from app.shared.analysis_tools.repository_map import (
        MAX_PARSE_BYTES,
        RepositoryMappingEngine,
    )

    files = {
        "src/App.tsx": "export const A = 1;\n",
        "public/bundle.js": "x" * (MAX_PARSE_BYTES + 1024),
        "public/min.js": ("a" * 2000 + "\n") * 30,
    }
    repo_map = RepositoryMappingEngine().create_map(files)

    assert "AST-mapping cap" in repo_map.files["public/bundle.js"].errors[0]
    assert "minified" in repo_map.files["public/min.js"].errors[0]
    assert repo_map.files["src/App.tsx"].errors == []
