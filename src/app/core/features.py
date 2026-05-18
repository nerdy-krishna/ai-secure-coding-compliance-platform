"""Feature-flag catalog and persistence helpers (modular setup — issue #103).

A *feature* is a runtime-toggleable platform capability. The enabled-feature
set is persisted as ``features.<name>`` rows in the ``system_config`` table and
mirrored into :class:`~app.core.config_cache.SystemConfigCache`.

This module owns three things:

  * the **catalog** — the set of features and their dependency edges;
  * **dependency resolution** — closing a requested set under its deps;
  * **persistence** — load / seed-if-empty against ``system_config``.

Scope of issue #103 is the mechanism plus the first two catalog entries
(``scan`` and ``chat``). The remaining 11 features and the variant presets
arrive in issues #104 / #105 — adding a catalog entry here is all that those
need to participate.
"""

from __future__ import annotations

import logging
from collections import namedtuple
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, FrozenSet, Iterable, List, Set

if TYPE_CHECKING:
    from app.infrastructure.database.repositories.system_config_repo import (
        SystemConfigRepository,
    )

logger = logging.getLogger(__name__)

#: ``system_config`` key prefix for per-feature flag rows.
FEATURE_FLAG_PREFIX = "features."


@dataclass(frozen=True)
class Feature:
    """One catalog entry."""

    name: str
    description: str
    #: Names of features this one requires. ``resolve_dependencies`` closes a
    #: requested set over these edges; an enabled set is never allowed to
    #: contain a feature without its dependencies.
    depends_on: FrozenSet[str] = frozenset()
    #: True when the feature needs an optional docker-compose container to be
    #: running (e.g. ``log_stack``, ``tracing``). The lifespan consistency
    #: check warns when such a feature is enabled but its ``compose_profile``
    #: is absent from ``COMPOSE_PROFILES``.
    container_backed: bool = False
    #: For a container-backed feature, the docker-compose profile that must be
    #: in ``COMPOSE_PROFILES`` for its containers to run.
    compose_profile: str | None = None
    #: Always-on features cannot be disabled — ``scan`` is the product floor.
    always_on: bool = False


FEATURE_CATALOG: Dict[str, Feature] = {
    "scan": Feature(
        name="scan",
        description=(
            "Code submission, SAST prescan, LLM audit/remediate, findings, "
            "dashboard. The product floor — always on."
        ),
        always_on=True,
    ),
    "chat": Feature(
        name="chat",
        description="Security Advisor chat.",
        depends_on=frozenset({"scan"}),
    ),
    "compliance": Feature(
        name="compliance",
        description="ASVS / MASVS posture and compliance reports.",
        depends_on=frozenset({"scan"}),
    ),
    "multi_user": Feature(
        name="multi_user",
        description="Non-superuser accounts and user management.",
    ),
    "user_groups": Feature(
        name="user_groups",
        description="Peer visibility scope (H.2) and group management.",
        depends_on=frozenset({"multi_user"}),
    ),
    "sso": Feature(
        name="sso",
        description="OIDC / SAML single sign-on and the SSO audit log.",
        depends_on=frozenset({"multi_user"}),
    ),
    "scim": Feature(
        name="scim",
        description="SCIM 2.0 provisioning tokens and endpoints.",
        depends_on=frozenset({"sso"}),
    ),
    "multi_tenant": Feature(
        name="multi_tenant",
        description="Tenant management and tenant isolation.",
        depends_on=frozenset({"multi_user"}),
    ),
    "email": Feature(
        name="email",
        description="SMTP — password-reset and notification email.",
    ),
    "log_stack": Feature(
        name="log_stack",
        description="LLM log viewer plus the Fluentd / Loki / Grafana stack.",
        container_backed=True,
        compose_profile="log_stack",
    ),
    "tracing": Feature(
        name="tracing",
        description="Per-LLM-call traces via the self-hosted Langfuse stack.",
        container_backed=True,
        compose_profile="tracing",
    ),
    "mcp": Feature(
        name="mcp",
        description="The /mcp tool surface for external agents.",
        depends_on=frozenset({"scan"}),
    ),
    "admin_authoring": Feature(
        name="admin_authoring",
        description="Agent / framework / prompt / RAG admin authoring.",
    ),
}

#: Every catalog feature name.
ALL_FEATURES: FrozenSet[str] = frozenset(FEATURE_CATALOG)

#: Features enabled when nothing has been seeded yet. Until the variant layer
#: (issue #105) lands, the default is "everything on" so fresh and existing
#: installs alike behave exactly as they did before the flag system existed.
DEFAULT_ENABLED_FEATURES: FrozenSet[str] = ALL_FEATURES


def is_known_feature(name: str) -> bool:
    """True when ``name`` is a catalog feature."""
    return name in FEATURE_CATALOG


def resolve_dependencies(requested: Iterable[str]) -> Set[str]:
    """Close ``requested`` under the dependency graph and always-on features.

    Returns a new set containing every requested *known* feature, the
    transitive ``depends_on`` of each, and every ``always_on`` feature.
    Unknown names are dropped. This is the single chokepoint guaranteeing an
    enabled set is dependency-consistent — callers persisting or applying a
    feature set should pass it through here first.
    """
    resolved: Set[str] = set()
    queue: List[str] = [n for n in requested if n in FEATURE_CATALOG]
    queue += [n for n, f in FEATURE_CATALOG.items() if f.always_on]
    while queue:
        name = queue.pop()
        if name in resolved:
            continue
        resolved.add(name)
        queue.extend(FEATURE_CATALOG[name].depends_on)
    return resolved


def parse_enabled_from_rows(rows: Iterable) -> Set[str]:
    """Derive the enabled-feature set from ``system_config`` rows.

    ``rows`` is any iterable of objects with ``.key`` / ``.value`` (the
    ``SystemConfiguration`` ORM model, or test doubles). A ``features.<name>``
    row is enabled when its value is ``{"enabled": true}``. A catalog feature
    with *no* row falls back to its ``DEFAULT_ENABLED_FEATURES`` membership so
    a catalog grown in a later release degrades gracefully against a DB seeded
    by an earlier one. The result is dependency-resolved.
    """
    seen: Dict[str, bool] = {}
    for row in rows:
        key = getattr(row, "key", "") or ""
        if not key.startswith(FEATURE_FLAG_PREFIX):
            continue
        name = key[len(FEATURE_FLAG_PREFIX) :]
        value = getattr(row, "value", None)
        if isinstance(value, dict):
            enabled = bool(value.get("enabled"))
        else:
            enabled = bool(value)
        seen[name] = enabled
    requested: Set[str] = set()
    for name in FEATURE_CATALOG:
        if name in seen:
            if seen[name]:
                requested.add(name)
        elif name in DEFAULT_ENABLED_FEATURES:
            requested.add(name)
    return resolve_dependencies(requested)


async def load_or_seed_enabled_features(repo: "SystemConfigRepository") -> Set[str]:
    """Return the enabled-feature set, seeding default rows when none exist.

    On the first call against an un-seeded ``system_config`` (no
    ``features.*`` rows) this writes one row per catalog feature reflecting
    ``DEFAULT_ENABLED_FEATURES``, then returns that set. On every later call it
    just reads and parses the existing rows — the seed never overwrites
    operator changes (the empty-table guard).
    """
    rows = await repo.get_all()
    has_feature_rows = any(
        (getattr(r, "key", "") or "").startswith(FEATURE_FLAG_PREFIX) for r in rows
    )
    if not has_feature_rows:
        await _seed_default_feature_rows(repo)
        logger.info(
            "features.seeded", extra={"enabled": sorted(DEFAULT_ENABLED_FEATURES)}
        )
        return resolve_dependencies(DEFAULT_ENABLED_FEATURES)
    return parse_enabled_from_rows(rows)


async def _seed_default_feature_rows(repo: "SystemConfigRepository") -> None:
    """Write one ``features.<name>`` row per catalog feature (default state)."""
    from app.api.v1 import models as api_models

    for name, feature in FEATURE_CATALOG.items():
        await repo.set_value(
            api_models.SystemConfigurationCreate(
                key=f"{FEATURE_FLAG_PREFIX}{name}",
                value={"enabled": name in DEFAULT_ENABLED_FEATURES},
                description=f"Feature flag: {feature.description}",
                is_secret=False,
                encrypted=False,
            )
        )


#: Lightweight row carrier for the synchronous bootstrap read — duck-types
#: the ``.key`` / ``.value`` attributes ``parse_enabled_from_rows`` expects.
_FeatureRow = namedtuple("_FeatureRow", ["key", "value"])


def bootstrap_enabled_features_sync() -> Set[str]:
    """Read the enabled-feature set synchronously at app-import time.

    Router mounting in ``main.py`` happens at module import — before the
    lifespan, and (under uvicorn) from *inside* the server's event loop, so an
    async query is not an option. This uses a short-lived synchronous psycopg
    connection instead.

    Read-only: it never seeds. On a fresh, un-seeded install it finds no
    ``features.*`` rows and returns ``DEFAULT_ENABLED_FEATURES`` (every router
    mounted) — seeding is the job of the lifespan / the ``/setup`` endpoint.
    Fail-open on any error (DB unreachable, table not yet migrated): a
    boot-time hiccup never strands the app with missing routers, and the
    lifespan re-loads the flag set authoritatively once the DB is reachable.
    """
    try:
        rows = _read_feature_rows_sync()
    except Exception:
        logger.warning(
            "features.bootstrap_failed; defaulting to all features", exc_info=True
        )
        return resolve_dependencies(DEFAULT_ENABLED_FEATURES)
    if not rows:
        return resolve_dependencies(DEFAULT_ENABLED_FEATURES)
    return parse_enabled_from_rows(rows)


def _read_feature_rows_sync() -> List[_FeatureRow]:
    """Read ``features.*`` rows over a short-lived synchronous connection."""
    import psycopg

    from app.config.config import settings

    dsn = (settings.ASYNC_DATABASE_URL or "").replace(
        "postgresql+asyncpg", "postgresql"
    )
    if not dsn:
        return []
    rows: List[_FeatureRow] = []
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT key, value FROM system_configurations WHERE key LIKE %s",
                (f"{FEATURE_FLAG_PREFIX}%",),
            )
            for key, value in cur.fetchall():
                # psycopg adapts a jsonb column to a Python dict directly.
                rows.append(_FeatureRow(key=key, value=value))
    return rows
