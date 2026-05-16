"""Framework-agnostic RAG metadata facet resolver (Framework Expansion #56).

A scan agent declares *what reference material it wants* through its
``domain_query.metadata_filter`` — a small dict of facet → value(s). This
module is the single, pure place that translates that declaration into a
Chroma-style ``where`` clause. The clause is then handed to
``qdrant_store._translate_filter`` unchanged, so this module never imports
``qdrant_client`` and stays trivially testable as a dict → dict function.

Why a dedicated facet vocabulary
--------------------------------
ASVS organises its corpus by ``control_family``. CWE Essentials organises
by *concern-area* (memory safety, injection, …) and ISVS by section —
neither fits the ASVS taxonomy. Rather than overload ``control_family``,
the resolver recognises a fixed **facet allowlist**: ``control_family``
stays the ASVS facet, and ``concern_area`` is the framework-agnostic facet
CWE Essentials and ISVS tag their documents with. ``control_family`` is
now simply one facet among several.

Taxonomy *values* (the concern-area names, ISVS section labels) are owned
by the per-framework seed data and the corpus tagging — not by this
module. The resolver only fixes the set of *keys* a query may filter on.

Anchor
------
Every resolved clause anchors ``scan_ready == True`` so chat-only RAG
documents (Proactive Controls / Cheatsheets narrative content) are never
returned to a server-side scan.

Note: this module is intentionally *not yet wired in*. ``analysis_node``
in ``generic_specialized_agent.py`` still calls its own ``_build_rag_filter``;
the swap happens in the per-framework split (#57). One deliberate
difference from that legacy helper: its allowlist omits ``control_family``,
so ASVS agents' family filter is silently dropped today. The resolver
includes ``control_family`` — the gap is fixed at the #57 swap, not here.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Anchored on every clause — keeps chat-only docs out of scan retrieval.
ANCHOR_KEY = "scan_ready"

# The framework-agnostic concern facet. CWE Essentials concern-areas and
# ISVS sections are expressed through this key; its values are free-form
# strings owned by each framework's corpus tagging.
CONCERN_FACET = "concern_area"

# Allowlist of metadata keys an agent's `metadata_filter` may target.
# Anything outside this set is dropped with a warning — an agent cannot
# filter RAG retrieval on an arbitrary payload key.
FACET_KEYS: frozenset[str] = frozenset(
    {
        "framework_name",  # scope retrieval to one framework's corpus
        "control_family",  # ASVS facet
        CONCERN_FACET,  # CWE Essentials concern-area / ISVS section facet
        "cwe_id",  # pin to a specific CWE
        "language",  # language-tagged guidance
        "category",  # generic topical bucket
    }
)


def resolve_rag_filter(domain_query: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Translate an agent's ``domain_query`` into a Chroma-style ``where`` clause.

    The returned dict is consumed unchanged by
    ``qdrant_store._translate_filter``. It always anchors
    ``scan_ready == True``; recognised facets from
    ``domain_query.metadata_filter`` are AND-ed onto that anchor.

    Per-facet value handling, mirroring the legacy ``_build_rag_filter``:

    * scalar value            → ``{key: {"$eq": value}}``
    * single-element list     → ``{key: {"$eq": value[0]}}``
    * multi-element list      → ``{"$or": [{key: {"$eq": v}}, ...]}``
    * empty list              → skipped (no constraint)

    Keys outside :data:`FACET_KEYS` are dropped with a warning. A missing
    or empty ``metadata_filter`` yields just the anchor clause.
    """
    and_conditions: List[Dict[str, Any]] = [{ANCHOR_KEY: {"$eq": True}}]

    metadata_filter: Any = (domain_query or {}).get("metadata_filter")
    if isinstance(metadata_filter, dict):
        for key, value in metadata_filter.items():
            if key not in FACET_KEYS:
                logger.warning(
                    "RAG facet key rejected (not in allowlist)",
                    extra={"key": key},
                )
                continue
            clause = _facet_clause(key, value)
            if clause is not None:
                and_conditions.append(clause)
    elif metadata_filter is not None:
        logger.warning(
            "RAG metadata_filter is not a dict; ignoring",
            extra={"type": type(metadata_filter).__name__},
        )

    if len(and_conditions) > 1:
        return {"$and": and_conditions}
    return and_conditions[0]


def _facet_clause(key: str, value: Any) -> Optional[Dict[str, Any]]:
    """Build the ``where`` sub-clause for one allowlisted facet.

    Returns ``None`` when the facet carries nothing to constrain on (an
    empty list) so the caller can skip it.
    """
    if isinstance(value, list):
        if not value:
            return None
        if len(value) == 1:
            return {key: {"$eq": value[0]}}
        return {"$or": [{key: {"$eq": item}} for item in value]}
    return {key: {"$eq": value}}
