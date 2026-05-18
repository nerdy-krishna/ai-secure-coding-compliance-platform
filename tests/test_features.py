# tests/test_features.py
#
# Covers the feature-flag mechanism (modular setup — issue #103):
#   - the catalog and dependency resolver
#   - parse / load / seed-if-empty against system_config rows
#   - GET /api/v1/features
#   - the require_feature() dependency's 404 behaviour
#   - the conditional-mount decision input for the chat router
#
# Persistence is exercised against an in-memory fake repo so the seed-if-empty
# guard is deterministic regardless of what the shared dev DB already holds.

from __future__ import annotations

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.api.v1 import models as api_models
from app.api.v1.dependencies import require_feature
from app.core import features
from app.core.config_cache import SystemConfigCache


# ----------------------------------------------------------------------
# Fake system_config repository
# ----------------------------------------------------------------------
class FakeSystemConfigRepo:
    """Minimal stand-in for SystemConfigRepository.

    Stores SystemConfigurationCreate objects directly — they carry the
    ``.key`` / ``.value`` attributes the feature helpers read.
    """

    def __init__(self, rows=None):
        self._rows = list(rows or [])

    async def get_all(self):
        return list(self._rows)

    async def set_value(self, config):
        for i, row in enumerate(self._rows):
            if row.key == config.key:
                self._rows[i] = config
                return config
        self._rows.append(config)
        return config


def _flag_row(name: str, enabled: bool):
    return api_models.SystemConfigurationCreate(
        key=f"{features.FEATURE_FLAG_PREFIX}{name}",
        value={"enabled": enabled},
        description="test feature flag",
        is_secret=False,
        encrypted=False,
    )


# ----------------------------------------------------------------------
# Catalog + dependency resolver (pure)
# ----------------------------------------------------------------------
def test_catalog_contains_scan_and_chat():
    assert "scan" in features.FEATURE_CATALOG
    assert "chat" in features.FEATURE_CATALOG
    assert features.FEATURE_CATALOG["scan"].always_on is True
    assert "scan" in features.FEATURE_CATALOG["chat"].depends_on


def test_resolve_dependencies_pulls_deps_and_always_on():
    # Requesting only chat must pull in its dependency scan.
    assert features.resolve_dependencies({"chat"}) == {"chat", "scan"}
    # always_on features appear even when nothing is requested.
    assert "scan" in features.resolve_dependencies(set())


def test_resolve_dependencies_drops_unknown_names():
    assert features.resolve_dependencies({"chat", "bogus"}) == {"chat", "scan"}


# ----------------------------------------------------------------------
# parse_enabled_from_rows
# ----------------------------------------------------------------------
def test_parse_enabled_from_rows_respects_disabled_flag():
    enabled = features.parse_enabled_from_rows(
        [_flag_row("scan", True), _flag_row("chat", False)]
    )
    assert "chat" not in enabled
    # scan is always_on — present regardless of any row state.
    assert "scan" in enabled


def test_parse_missing_row_falls_back_to_default():
    # Only a scan row present; chat has no row → falls back to its
    # DEFAULT_ENABLED_FEATURES membership (enabled).
    enabled = features.parse_enabled_from_rows([_flag_row("scan", True)])
    assert "chat" in enabled


# ----------------------------------------------------------------------
# load_or_seed_enabled_features — seed-if-empty guard
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_load_or_seed_seeds_when_no_feature_rows():
    repo = FakeSystemConfigRepo()
    enabled = await features.load_or_seed_enabled_features(repo)
    assert enabled == features.resolve_dependencies(
        features.DEFAULT_ENABLED_FEATURES
    )
    # One features.* row written per catalog entry.
    rows = await repo.get_all()
    feature_rows = [r for r in rows if r.key.startswith(features.FEATURE_FLAG_PREFIX)]
    assert len(feature_rows) == len(features.FEATURE_CATALOG)


@pytest.mark.asyncio
async def test_load_or_seed_does_not_overwrite_existing_rows():
    # An operator has already disabled chat. Seeding must not run again.
    repo = FakeSystemConfigRepo([_flag_row("scan", True), _flag_row("chat", False)])
    enabled = await features.load_or_seed_enabled_features(repo)
    assert "chat" not in enabled
    # No extra rows appended — exactly the two we provided remain.
    assert len(await repo.get_all()) == 2


# ----------------------------------------------------------------------
# Conditional-mount decision input
# ----------------------------------------------------------------------
def test_chat_excluded_from_enabled_set_when_flag_disabled():
    # This set is exactly what main.py's `if "chat" in _enabled_features`
    # gate consumes to decide whether to mount the chat router.
    enabled = features.parse_enabled_from_rows(
        [_flag_row("scan", True), _flag_row("chat", False)]
    )
    assert "chat" not in enabled


# ----------------------------------------------------------------------
# require_feature() dependency
# ----------------------------------------------------------------------
def test_require_feature_404_when_disabled():
    previous = SystemConfigCache.get_enabled_features()
    try:
        SystemConfigCache.set_enabled_features({"scan"})
        dependency = require_feature("chat")
        with pytest.raises(HTTPException) as exc:
            dependency()
        assert exc.value.status_code == 404
    finally:
        SystemConfigCache.set_enabled_features(previous)


def test_require_feature_passes_when_enabled():
    previous = SystemConfigCache.get_enabled_features()
    try:
        SystemConfigCache.set_enabled_features({"scan", "chat"})
        # Should not raise.
        require_feature("chat")()
    finally:
        SystemConfigCache.set_enabled_features(previous)


# ----------------------------------------------------------------------
# GET /api/v1/features
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_features_endpoint_returns_enabled_set():
    from app.main import app

    previous = SystemConfigCache.get_enabled_features()
    try:
        SystemConfigCache.set_enabled_features({"scan"})
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            res = await client.get("/api/v1/features")
        assert res.status_code == 200
        body = res.json()
        assert body["enabled_features"] == ["scan"]
        assert "chat" in body["all_features"]
        assert "scan" in body["all_features"]
    finally:
        SystemConfigCache.set_enabled_features(previous)
