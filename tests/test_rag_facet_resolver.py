"""Framework Expansion #56 — RAG metadata facet resolver.

`resolve_rag_filter` is the single pure translation from an agent's
`domain_query` to a Chroma-style `where` clause. A wrong filter here
silently mis-routes reference docs across frameworks with no error, so
every facet → clause shape is pinned, plus the round-trip into the
existing Qdrant `where`→`Filter` translator.
"""

from __future__ import annotations

import pytest

from app.infrastructure.rag.facet_resolver import (
    ANCHOR_KEY,
    CONCERN_FACET,
    FACET_KEYS,
    resolve_rag_filter,
)


def _anchor() -> dict:
    return {ANCHOR_KEY: {"$eq": True}}


# --------------------------------------------------------------------------
# Anchor — every clause keeps chat-only docs out of scan retrieval.
# --------------------------------------------------------------------------


def test_none_domain_query_yields_only_anchor():
    assert resolve_rag_filter(None) == _anchor()


def test_empty_domain_query_yields_only_anchor():
    assert resolve_rag_filter({}) == _anchor()


def test_missing_metadata_filter_yields_only_anchor():
    assert resolve_rag_filter({"keywords": "sql injection"}) == _anchor()


def test_empty_metadata_filter_yields_only_anchor():
    assert resolve_rag_filter({"metadata_filter": {}}) == _anchor()


# --------------------------------------------------------------------------
# ASVS facet — `control_family`. Must survive the resolver (the legacy
# `_build_rag_filter` allowlist drops it; the resolver keeps it).
# --------------------------------------------------------------------------


def test_control_family_single_value_is_eq_clause():
    out = resolve_rag_filter({"metadata_filter": {"control_family": ["Authorization"]}})
    assert out == {"$and": [_anchor(), {"control_family": {"$eq": "Authorization"}}]}


def test_control_family_multi_value_is_or_clause():
    out = resolve_rag_filter(
        {
            "metadata_filter": {
                "control_family": ["API and Web Service", "OAuth and OIDC"]
            }
        }
    )
    assert out == {
        "$and": [
            _anchor(),
            {
                "$or": [
                    {"control_family": {"$eq": "API and Web Service"}},
                    {"control_family": {"$eq": "OAuth and OIDC"}},
                ]
            },
        ]
    }


def test_control_family_is_an_allowlisted_facet():
    """Regression guard for the legacy allowlist gap — `control_family`
    must be a recognised facet so ASVS family filtering actually works."""
    assert "control_family" in FACET_KEYS


# --------------------------------------------------------------------------
# Framework-agnostic concern facet — used by CWE Essentials concern-areas
# and ISVS sections. The same key serves both frameworks.
# --------------------------------------------------------------------------


def test_concern_area_facet_for_cwe_concern_area():
    out = resolve_rag_filter(
        {"metadata_filter": {CONCERN_FACET: ["Spatial Memory Safety"]}}
    )
    assert out == {
        "$and": [_anchor(), {CONCERN_FACET: {"$eq": "Spatial Memory Safety"}}]
    }


def test_concern_area_facet_for_isvs_section():
    out = resolve_rag_filter(
        {"metadata_filter": {CONCERN_FACET: ["Firmware", "Hardware Platform"]}}
    )
    assert out == {
        "$and": [
            _anchor(),
            {
                "$or": [
                    {CONCERN_FACET: {"$eq": "Firmware"}},
                    {CONCERN_FACET: {"$eq": "Hardware Platform"}},
                ]
            },
        ]
    }


def test_concern_facet_key_is_framework_agnostic():
    assert CONCERN_FACET in FACET_KEYS


# --------------------------------------------------------------------------
# Other allowlisted facets.
# --------------------------------------------------------------------------


def test_framework_name_scalar_facet():
    out = resolve_rag_filter({"metadata_filter": {"framework_name": "asvs"}})
    assert out == {"$and": [_anchor(), {"framework_name": {"$eq": "asvs"}}]}


def test_cwe_id_facet():
    out = resolve_rag_filter({"metadata_filter": {"cwe_id": ["CWE-787"]}})
    assert out == {"$and": [_anchor(), {"cwe_id": {"$eq": "CWE-787"}}]}


def test_multiple_facets_are_and_ed_onto_the_anchor():
    out = resolve_rag_filter(
        {
            "metadata_filter": {
                "framework_name": "cwe_essentials",
                CONCERN_FACET: ["OS & Command Injection"],
            }
        }
    )
    assert out["$and"][0] == _anchor()
    rest = out["$and"][1:]
    assert {"framework_name": {"$eq": "cwe_essentials"}} in rest
    assert {CONCERN_FACET: {"$eq": "OS & Command Injection"}} in rest
    assert len(rest) == 2


# --------------------------------------------------------------------------
# Rejection / robustness.
# --------------------------------------------------------------------------


def test_unknown_facet_key_is_dropped():
    """A key outside the allowlist must not reach the filter — an agent
    cannot filter retrieval on an arbitrary payload key."""
    out = resolve_rag_filter({"metadata_filter": {"definitely_not_a_facet": ["x"]}})
    assert out == _anchor()


def test_known_facet_survives_alongside_rejected_key():
    out = resolve_rag_filter(
        {
            "metadata_filter": {
                "bogus": "drop me",
                "control_family": ["Cryptography"],
            }
        }
    )
    assert out == {"$and": [_anchor(), {"control_family": {"$eq": "Cryptography"}}]}


def test_empty_list_facet_is_skipped():
    out = resolve_rag_filter({"metadata_filter": {"control_family": []}})
    assert out == _anchor()


def test_non_dict_metadata_filter_is_ignored():
    out = resolve_rag_filter({"metadata_filter": ["not", "a", "dict"]})
    assert out == _anchor()


# --------------------------------------------------------------------------
# Integration — resolver output must be accepted unchanged by the existing
# Qdrant `where`→`Filter` translator.
# --------------------------------------------------------------------------


def test_resolver_output_is_accepted_by_qdrant_translator():
    pytest.importorskip("qdrant_client.http.models")
    from app.infrastructure.rag.qdrant_store import _translate_filter

    for domain_query in (
        None,
        {"metadata_filter": {"control_family": ["Authorization"]}},
        {
            "metadata_filter": {
                "control_family": ["API and Web Service", "OAuth and OIDC"]
            }
        },
        {
            "metadata_filter": {
                "framework_name": "cwe_essentials",
                CONCERN_FACET: ["Spatial Memory Safety", "Temporal Memory Safety"],
            }
        },
    ):
        where = resolve_rag_filter(domain_query)
        # Must not raise — the translator covers every operator the
        # resolver emits ($and / $or / $eq).
        _translate_filter(where)
