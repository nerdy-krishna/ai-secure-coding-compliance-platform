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


def test_catalog_has_all_thirteen_features():
    expected = {
        "scan",
        "chat",
        "compliance",
        "multi_user",
        "user_groups",
        "sso",
        "scim",
        "multi_tenant",
        "email",
        "log_stack",
        "tracing",
        "mcp",
        "admin_authoring",
    }
    assert set(features.FEATURE_CATALOG) == expected


def test_container_backed_features_carry_a_compose_profile():
    for name in ("log_stack", "tracing"):
        feat = features.FEATURE_CATALOG[name]
        assert feat.container_backed is True
        assert feat.compose_profile == name


def test_resolve_dependencies_pulls_deps_and_always_on():
    # Requesting only chat must pull in its dependency scan.
    assert features.resolve_dependencies({"chat"}) == {"chat", "scan"}
    # always_on features appear even when nothing is requested.
    assert "scan" in features.resolve_dependencies(set())


def test_resolve_dependencies_closes_transitive_chain():
    # scim -> sso -> multi_user must all be pulled in.
    resolved = features.resolve_dependencies({"scim"})
    assert {"scim", "sso", "multi_user"}.issubset(resolved)


def test_resolve_dependencies_collaboration_chain():
    assert "multi_user" in features.resolve_dependencies({"user_groups"})
    assert "multi_user" in features.resolve_dependencies({"multi_tenant"})


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
async def test_load_or_seed_seeds_from_variant(monkeypatch):
    monkeypatch.setenv("SCCAP_VARIANT", "vibe_coder")
    repo = FakeSystemConfigRepo()
    enabled = await features.load_or_seed_enabled_features(repo)
    assert enabled == features.expand_variant("vibe_coder")
    # One features.* row written per catalog entry.
    rows = await repo.get_all()
    feature_rows = [r for r in rows if r.key.startswith(features.FEATURE_FLAG_PREFIX)]
    assert len(feature_rows) == len(features.FEATURE_CATALOG)
    # vibe_coder seeds chat enabled, sso disabled.
    by_key = {r.key: r.value for r in feature_rows}
    assert by_key["features.chat"]["enabled"] is True
    assert by_key["features.sso"]["enabled"] is False


@pytest.mark.asyncio
async def test_load_or_seed_unset_variant_falls_back_to_enterprise(monkeypatch):
    monkeypatch.delenv("SCCAP_VARIANT", raising=False)
    repo = FakeSystemConfigRepo()
    enabled = await features.load_or_seed_enabled_features(repo)
    assert enabled == features.expand_variant("enterprise")


@pytest.mark.asyncio
async def test_load_or_seed_does_not_overwrite_existing_rows():
    # An operator has already disabled chat. Seeding must not run again.
    repo = FakeSystemConfigRepo([_flag_row("scan", True), _flag_row("chat", False)])
    enabled = await features.load_or_seed_enabled_features(repo)
    assert "chat" not in enabled
    # No extra rows appended — exactly the two we provided remain.
    assert len(await repo.get_all()) == 2


# ----------------------------------------------------------------------
# Variant presets + resolver (issue #105)
# ----------------------------------------------------------------------
def test_expand_variant_vibe_coder():
    assert features.expand_variant("vibe_coder") == {"scan", "chat", "compliance"}


def test_expand_variant_developer_excludes_enterprise_features():
    dev = features.expand_variant("developer")
    assert {"multi_user", "user_groups", "mcp", "admin_authoring"}.issubset(dev)
    for enterprise_only in ("sso", "scim", "multi_tenant", "log_stack", "tracing"):
        assert enterprise_only not in dev


def test_expand_variant_enterprise_has_all_but_tracing():
    ent = features.expand_variant("enterprise")
    assert ent == features.ALL_FEATURES - {"tracing"}


def test_expand_variant_custom_is_everything():
    assert features.expand_variant("custom") == set(features.ALL_FEATURES)


def test_expand_variant_unknown_falls_back_to_enterprise():
    assert features.expand_variant("") == features.expand_variant("enterprise")
    assert features.expand_variant("bogus") == features.expand_variant("enterprise")


def test_prune_unsatisfied_drops_dependents():
    # multi_user removed → sso, scim, user_groups, multi_tenant all drop.
    full = set(features.ALL_FEATURES)
    pruned = features.prune_unsatisfied(full - {"multi_user"})
    for dependent in ("sso", "scim", "user_groups", "multi_tenant"):
        assert dependent not in pruned
    # Independent features survive.
    assert {"compliance", "email", "log_stack"}.issubset(pruned)


def test_prune_unsatisfied_keeps_always_on():
    assert "scan" in features.prune_unsatisfied(set())


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
