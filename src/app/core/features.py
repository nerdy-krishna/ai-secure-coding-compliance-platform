"""Feature-flag catalog and persistence helpers (modular setup — issue #103).

A *feature* is a runtime-toggleable platform capability. The enabled-feature
set is persisted as ``features.<name>`` rows in the ``system_config`` table and
mirrored into :class:`~app.core.config_cache.SystemConfigCache`.

This module owns four things:

  * the **catalog** — the 13 features and their dependency edges;
  * **dependency resolution** — closing a requested set under its deps
    (``resolve_dependencies``) and the disable-direction counterpart
    (``prune_unsatisfied``);
  * **variants** — the ``vibe_coder`` / ``developer`` / ``enterprise``
    presets and ``expand_variant``;
  * **persistence** — variant-seeded load / seed-if-empty against
    ``system_config``.

Adding a catalog entry plus, optionally, a variant-preset membership is all
a new feature needs to participate in modular setup.
"""

from __future__ import annotations

import logging
import os
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

#: Fallback membership for a catalog feature that has *no* ``features.*`` row
#: — used by ``parse_enabled_from_rows`` so a catalog grown in a later release
#: degrades gracefully (the feature reads as enabled) against a DB seeded by
#: an earlier one. This is *not* the seed default; seeding is variant-driven.
DEFAULT_ENABLED_FEATURES: FrozenSet[str] = ALL_FEATURES


# --- Variants (modular setup — issue #105) -----------------------------------
# A variant is a named preset of enabled features chosen at install time
# (setup.sh writes SCCAP_VARIANT). The three presets below plus `custom`
# (operator-picked) are the packaging tiers.
VARIANT_VIBE_CODER = "vibe_coder"
VARIANT_DEVELOPER = "developer"
VARIANT_ENTERPRISE = "enterprise"
VARIANT_CUSTOM = "custom"

#: Per-variant feature presets (pre-dependency-resolution — ``expand_variant``
#: closes them). ``enterprise`` deliberately omits ``tracing``: the Langfuse
#: stack is *available* (its compose profile ships) but the flag starts OFF
#: so a 6-container stack does not boot unasked. ``custom`` has no preset —
#: it is refined by the setup wizard / admin Features page.
VARIANT_PRESETS: Dict[str, FrozenSet[str]] = {
    VARIANT_VIBE_CODER: frozenset({"scan", "chat", "compliance"}),
    VARIANT_DEVELOPER: frozenset(
        {
            "scan",
            "chat",
            "compliance",
            "multi_user",
            "user_groups",
            "email",
            "mcp",
            "admin_authoring",
        }
    ),
    VARIANT_ENTERPRISE: frozenset(ALL_FEATURES - {"tracing"}),
}


def expand_variant(variant: str) -> Set[str]:
    """Return the dependency-resolved enabled set for a variant name.

    A known preset expands to its preset; ``custom`` expands to every feature
    (the wizard / admin Features page then refines it); an empty or unknown
    value falls back to the ``enterprise`` preset — the non-breaking default
    for an install with no ``SCCAP_VARIANT`` (e.g. one upgrading from before
    modular setup).
    """
    key = (variant or "").strip().lower()
    if key in VARIANT_PRESETS:
        return resolve_dependencies(VARIANT_PRESETS[key])
    if key == VARIANT_CUSTOM:
        return resolve_dependencies(ALL_FEATURES)
    return resolve_dependencies(VARIANT_PRESETS[VARIANT_ENTERPRISE])


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


def prune_unsatisfied(enabled: Iterable[str]) -> Set[str]:
    """Drop features whose dependencies are not all present.

    The disable-direction counterpart of ``resolve_dependencies``: where that
    *adds* dependencies, this *removes* dependents. Turning ``multi_user`` off
    must also turn ``sso`` / ``user_groups`` / ``multi_tenant`` off. Iterates
    to a fixed point, so a transitive chain (``scim`` → ``sso`` → ``multi_user``)
    collapses fully. Always-on features are always kept.
    """
    current: Set[str] = {n for n in enabled if n in FEATURE_CATALOG}
    current |= {n for n, f in FEATURE_CATALOG.items() if f.always_on}
    changed = True
    while changed:
        changed = False
        for name in list(current):
            if FEATURE_CATALOG[name].always_on:
                continue
            if not FEATURE_CATALOG[name].depends_on.issubset(current):
                current.discard(name)
                changed = True
    return current


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
    """Return the enabled-feature set, seeding from the variant when none exist.

    On the first call against an un-seeded ``system_config`` (no
    ``features.*`` rows) this expands ``SCCAP_VARIANT`` into the preset feature
    set, writes one ``features.<name>`` row per catalog feature, and returns
    that set. On every later call it just reads and parses the existing rows —
    the seed never overwrites operator changes (the empty-table guard).
    """
    rows = await repo.get_all()
    has_feature_rows = any(
        (getattr(r, "key", "") or "").startswith(FEATURE_FLAG_PREFIX) for r in rows
    )
    if not has_feature_rows:
        variant = os.environ.get("SCCAP_VARIANT", "")
        target = expand_variant(variant)
        await _seed_feature_rows(repo, target)
        logger.info(
            "features.seeded",
            extra={
                "variant": variant or "(unset→enterprise)",
                "enabled": sorted(target),
            },
        )
        return target
    return parse_enabled_from_rows(rows)


async def _seed_feature_rows(repo: "SystemConfigRepository", enabled: Set[str]) -> None:
    """Write one ``features.<name>`` row per catalog feature for ``enabled``."""
    from app.api.v1 import models as api_models

    for name, feature in FEATURE_CATALOG.items():
        await repo.set_value(
            api_models.SystemConfigurationCreate(
                key=f"{FEATURE_FLAG_PREFIX}{name}",
                value={"enabled": name in enabled},
                description=f"Feature flag: {feature.description}",
                is_secret=False,
                encrypted=False,
            )
        )


#: Lightweight row carrier for the synchronous bootstrap read — duck-types
#: the ``.key`` / ``.value`` attributes ``parse_enabled_from_rows`` expects.
_FeatureRow = namedtuple("_FeatureRow", ["key", "value"])


def catalog_metadata() -> List[dict]:
    """Static per-feature metadata — name, description, dependency edges,
    container-backed flag. Public (carries no flag state); consumed by the
    discovery endpoint and the setup wizard's custom-variant picker.
    """
    return [
        {
            "name": f.name,
            "description": f.description,
            "depends_on": sorted(f.depends_on),
            "container_backed": f.container_backed,
            "compose_profile": f.compose_profile,
            "always_on": f.always_on,
        }
        for f in (FEATURE_CATALOG[n] for n in sorted(FEATURE_CATALOG))
    ]


async def seed_features(
    repo: "SystemConfigRepository", requested: Iterable[str]
) -> Set[str]:
    """Seed ``features.*`` rows for an explicit requested set (custom variant).

    The request is dependency-resolved then pruned so the persisted set is
    always consistent. Used by the ``/setup`` endpoint when the wizard ran in
    custom mode; preset variants go through ``load_or_seed_enabled_features``.
    """
    final = prune_unsatisfied(resolve_dependencies(requested))
    await _seed_feature_rows(repo, final)
    logger.info(
        "features.seeded", extra={"variant": "custom", "enabled": sorted(final)}
    )
    return final


def bootstrap_enabled_features_sync() -> Set[str]:
    """Read the enabled-feature set synchronously at app-import time.

    Router mounting in ``main.py`` happens at module import — before the
    lifespan, and (under uvicorn) from *inside* the server's event loop, so an
    async query is not an option. This uses a short-lived synchronous psycopg
    connection instead.

    Read-only: it never seeds. On a fresh, un-seeded install it finds no
    ``features.*`` rows and falls back to the ``SCCAP_VARIANT`` preset so the
    first boot already mounts the right routers — actual seeding is the job
    of the lifespan / the ``/setup`` endpoint. Fail-open on any error (DB
    unreachable, table not yet migrated): a boot-time hiccup resolves to the
    variant preset too, and the lifespan re-loads authoritatively later.
    """
    try:
        rows = _read_feature_rows_sync()
    except Exception:
        logger.warning(
            "features.bootstrap_failed; falling back to SCCAP_VARIANT preset",
            exc_info=True,
        )
        return expand_variant(os.environ.get("SCCAP_VARIANT", ""))
    if not rows:
        return expand_variant(os.environ.get("SCCAP_VARIANT", ""))
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
