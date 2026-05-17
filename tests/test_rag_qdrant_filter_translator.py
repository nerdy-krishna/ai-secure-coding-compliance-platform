"""Threat-model G5 — Qdrant filter translator parity.

Walk every Chroma `where` operator the codebase actually uses and
assert the equivalent Qdrant `Filter` object is what we expect. Bugs
here cause silent over- or under-matching at PR2's read-flip — by
which point Chroma's no longer the source of truth.
"""

from __future__ import annotations

import pytest

# qdrant-client may not be importable in all CI legs; guard.
qdrant_models = pytest.importorskip("qdrant_client.http.models")


def _t(where):
    """Local import so the ImportError message is on the actual file
    that needs the package, not the test module."""
    from app.infrastructure.rag.qdrant_store import _translate_filter

    return _translate_filter(where)


def test_eq_single_key():
    """`{"k": {"$eq": v}}` → `must=[FieldCondition(MatchValue)]`."""
    out = _t({"framework_name": {"$eq": "asvs"}})
    assert out is not None
    assert out.must is not None and len(out.must) == 1
    cond = out.must[0]
    assert isinstance(cond, qdrant_models.FieldCondition)
    assert cond.key == "framework_name"
    assert cond.match.value == "asvs"


def test_ne_single_key():
    """`{"k": {"$ne": v}}` → `must_not=[FieldCondition(MatchValue)]`."""
    out = _t({"framework_name": {"$ne": "cheatsheets"}})
    assert out is not None
    assert out.must_not is not None and len(out.must_not) == 1
    assert out.must_not[0].match.value == "cheatsheets"


def test_in_list():
    """`{"k": {"$in": [...]]}}` → `must=[FieldCondition(MatchAny)]`."""
    out = _t({"framework_name": {"$in": ["asvs", "proactive_controls"]}})
    assert out is not None
    assert out.must is not None and len(out.must) == 1
    assert isinstance(out.must[0].match, qdrant_models.MatchAny)
    assert out.must[0].match.any == ["asvs", "proactive_controls"]


def test_and_of_eq():
    """`{"$and": [{"$eq"}, {"$eq"}]}` → `must=[..., ...]`."""
    out = _t(
        {
            "$and": [
                {"scan_ready": {"$eq": True}},
                {"framework_name": {"$eq": "asvs"}},
            ]
        }
    )
    assert out is not None
    assert out.must is not None and len(out.must) == 2


def test_or_of_eq():
    """`{"$or": [{"$eq"}, {"$eq"}]}` → `should=[Filter, Filter]`."""
    out = _t(
        {
            "$or": [
                {"framework_name": {"$eq": "asvs"}},
                {"framework_name": {"$eq": "cheatsheets"}},
            ]
        }
    )
    assert out is not None
    assert out.should is not None and len(out.should) == 2
    for child in out.should:
        assert isinstance(child, qdrant_models.Filter)


def test_analysis_node_filter_shape():
    """The literal filter built in `analysis_node` of
    `generic_specialized_agent.py` — `$and` of `scan_ready=True` and
    a multi-value `$or` — must translate without raising and without
    flattening the OR into the top-level AND."""
    out = _t(
        {
            "$and": [
                {"scan_ready": {"$eq": True}},
                {
                    "$or": [
                        {"category": {"$eq": "auth"}},
                        {"category": {"$eq": "validation"}},
                    ]
                },
            ]
        }
    )
    assert out is not None
    # `must` carries the scan_ready clause; the `$or` becomes a nested
    # Filter inside `must`.
    assert out.must is not None
    # At least one of the must entries should itself be a nested Filter
    # (the OR), and at least one should be a FieldCondition (scan_ready).
    has_nested = any(isinstance(c, qdrant_models.Filter) for c in out.must)
    has_field = any(isinstance(c, qdrant_models.FieldCondition) for c in out.must)
    assert has_nested and has_field


def test_implicit_equality_shorthand():
    """Chroma also accepts `{"k": v}` as shorthand for `$eq`."""
    out = _t({"framework_name": "asvs"})
    assert out is not None
    assert out.must is not None
    assert out.must[0].match.value == "asvs"


def test_unsupported_operator_raises():
    with pytest.raises(ValueError):
        _t({"k": {"$gt": 5}})


def test_none_returns_none():
    assert _t(None) is None
    assert _t({}) is None


def test_or_of_and_with_must_not_preserves_branch_semantics():
    """Security review F1 — `$or:[{$and:[a, not b]}, c]` MUST be
    equivalent to `(a AND NOT b) OR c`, not `(a) OR (NOT b) OR (c)`.

    The buggy translation flattens the $and child's `must` and
    `must_not` into separate `should` siblings, broadening the match.
    The fixed translation wraps each child in a single nested Filter
    so the branch keeps its AND-within-OR identity.
    """
    out = _t(
        {
            "$or": [
                {
                    "$and": [
                        {"category": {"$eq": "auth"}},
                        {"deprecated": {"$ne": True}},
                    ]
                },
                {"framework_name": {"$eq": "asvs"}},
            ]
        }
    )
    assert out is not None
    assert out.should is not None
    # Each $or branch becomes exactly one nested Filter, not 1+N
    # split conditions.
    assert len(out.should) == 2
    branch_a = out.should[0]
    assert isinstance(branch_a, qdrant_models.Filter)
    # The $and branch keeps both must (category=auth) and must_not
    # (deprecated=True) inside the SAME Filter.
    assert branch_a.must is not None and len(branch_a.must) == 1
    assert branch_a.must_not is not None and len(branch_a.must_not) == 1


def test_qdrant_id_is_uuid():
    """Security review F3 — chroma string ids are mapped to deterministic
    UUIDs so Qdrant accepts them. Same Chroma id → same UUID across calls."""
    from app.infrastructure.rag.qdrant_store import _qdrant_id

    a1 = _qdrant_id("asvs:1.2.3")
    a2 = _qdrant_id("asvs:1.2.3")
    b = _qdrant_id("asvs:9.9.9")
    assert a1 == a2
    assert a1 != b
    # UUID-shaped (5 hyphen-separated groups).
    assert len(a1.split("-")) == 5


def test_check_framework_name_accepts_any_configured_framework():
    """Framework name is validated by format — `get_by_framework` /
    `delete_by_framework` must accept frameworks added after the
    original three (CWE Essentials, ISVS) and admin-added custom ones,
    not a stale hardcoded enum."""
    from app.infrastructure.rag.qdrant_store import _check_framework_name

    # No raise — every one of these is a safe identifier.
    for name in ("asvs", "cwe_essentials", "isvs", "my-custom_framework"):
        _check_framework_name(name)


def test_check_framework_name_rejects_unsafe_input():
    """The format check still bounds charset + length so nothing unsafe
    reaches a Qdrant filter."""
    from app.infrastructure.rag.qdrant_store import _check_framework_name

    for bad in ("", "has spaces", "drop;table", "a" * 65, "../etc"):
        with pytest.raises(ValueError):
            _check_framework_name(bad)
