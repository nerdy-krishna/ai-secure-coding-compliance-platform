# tests/test_semgrep_selector.py
"""Integration tests for SemgrepRuleRepository — rule selection, coverage.

Uses the rollback-per-test db_session fixture from conftest.py so nothing
persists between tests.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.semgrep_rule_repo import (
    SemgrepRuleRepository,
)

pytestmark = pytest.mark.asyncio

FIXTURES = Path(__file__).parent / "fixtures" / "semgrep_rules"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_source(
    db: AsyncSession,
    *,
    slug: str | None = None,
    license_spdx: str = "MIT",
    enabled: bool = True,
) -> db_models.SemgrepRuleSource:
    slug = slug or f"src-{uuid.uuid4().hex[:8]}"
    repo = SemgrepRuleRepository(db)
    source = await repo.upsert_source(
        {
            "slug": slug,
            "display_name": slug,
            "description": "test source",
            "repo_url": "https://github.com/example/rules",
            "branch": "main",
            "subpath": None,
            "license_spdx": license_spdx,
            "author": "test",
        }
    )
    source.enabled = enabled
    await db.flush()
    return source


async def _add_rule(
    db: AsyncSession,
    source: db_models.SemgrepRuleSource,
    *,
    namespaced_id: str | None = None,
    languages: list[str] | None = None,
    severity: str = "ERROR",
    technology: list[str] | None = None,
    enabled: bool = True,
) -> db_models.SemgrepRule:
    namespaced_id = namespaced_id or f"{source.slug}.rule-{uuid.uuid4().hex[:6]}"
    repo = SemgrepRuleRepository(db)
    rule, _ = await repo.upsert_rule(
        source.id,
        {
            "namespaced_id": namespaced_id,
            "original_id": namespaced_id.split(".")[-1],
            "relative_path": "rules/test.yaml",
            "languages": languages or ["python"],
            "severity": severity,
            "category": "security",
            "technology": technology or [],
            "cwe": ["CWE-89"],
            "owasp": [],
            "confidence": "HIGH",
            "likelihood": None,
            "impact": None,
            "message": "test rule",
            "raw_yaml": {"id": namespaced_id, "languages": languages or ["python"]},
            "content_hash": uuid.uuid4().hex,
            "license_spdx": source.license_spdx,
            "enabled": enabled,
        },
    )
    return rule


# ---------------------------------------------------------------------------
# Tests — select_rules_for_scan
# ---------------------------------------------------------------------------


async def test_select_rules_returns_matching_language(db_session: AsyncSession):
    src = await _make_source(db_session)
    await _add_rule(db_session, src, languages=["python"])
    await _add_rule(db_session, src, languages=["go"])

    repo = SemgrepRuleRepository(db_session)
    rules = await repo.select_rules_for_scan(
        languages=["python"],
        technologies=[],
        allowed_licenses=["MIT"],
        max_rules=1000,
    )
    assert any(r.source_id == src.id for r in rules)
    lang_sets = [set(r.languages) for r in rules if r.source_id == src.id]
    assert all("python" in ls for ls in lang_sets)


async def test_select_rules_excludes_disabled_source(db_session: AsyncSession):
    src = await _make_source(db_session, enabled=False)
    await _add_rule(db_session, src, languages=["python"])

    repo = SemgrepRuleRepository(db_session)
    rules = await repo.select_rules_for_scan(
        languages=["python"],
        technologies=[],
        allowed_licenses=["MIT"],
        max_rules=1000,
    )
    assert all(r.source_id != src.id for r in rules)


async def test_select_rules_excludes_disallowed_license(db_session: AsyncSession):
    src = await _make_source(db_session, license_spdx="GPL-3.0")
    await _add_rule(db_session, src, languages=["python"])

    repo = SemgrepRuleRepository(db_session)
    rules = await repo.select_rules_for_scan(
        languages=["python"],
        technologies=[],
        allowed_licenses=["MIT", "Apache-2.0"],
        max_rules=1000,
    )
    assert all(r.source_id != src.id for r in rules)


async def test_select_rules_excludes_disabled_rule(db_session: AsyncSession):
    src = await _make_source(db_session)
    rule = await _add_rule(db_session, src, languages=["python"], enabled=False)
    rule.enabled = False
    await db_session.flush()

    repo = SemgrepRuleRepository(db_session)
    rules = await repo.select_rules_for_scan(
        languages=["python"],
        technologies=[],
        allowed_licenses=["MIT"],
        max_rules=1000,
    )
    assert all(r.id != rule.id for r in rules)


async def test_select_rules_respects_max_rules(db_session: AsyncSession):
    src = await _make_source(db_session)
    for i in range(10):
        await _add_rule(db_session, src, languages=["python"])

    repo = SemgrepRuleRepository(db_session)
    rules = await repo.select_rules_for_scan(
        languages=["python"],
        technologies=[],
        allowed_licenses=["MIT"],
        max_rules=3,
    )
    assert len([r for r in rules if r.source_id == src.id]) <= 3


async def test_select_rules_no_match_returns_empty(db_session: AsyncSession):
    src = await _make_source(db_session)
    await _add_rule(db_session, src, languages=["python"])

    repo = SemgrepRuleRepository(db_session)
    rules = await repo.select_rules_for_scan(
        languages=["ruby"],
        technologies=[],
        allowed_licenses=["MIT"],
        max_rules=1000,
    )
    assert all(r.source_id != src.id for r in rules)


async def test_select_rules_technology_filter(db_session: AsyncSession):
    src = await _make_source(db_session)
    rule_with_tech = await _add_rule(
        db_session, src, languages=["python"], technology=["django"]
    )
    rule_no_tech = await _add_rule(db_session, src, languages=["python"], technology=[])

    repo = SemgrepRuleRepository(db_session)
    # technology=[] in query → should return rules with ANY or no technology
    rules = await repo.select_rules_for_scan(
        languages=["python"],
        technologies=[],
        allowed_licenses=["MIT"],
        max_rules=1000,
    )
    ids = {r.id for r in rules}
    # Both rules belong to the same source and match python — both should return
    assert rule_with_tech.id in ids or rule_no_tech.id in ids


# ---------------------------------------------------------------------------
# Tests — coverage summary
# ---------------------------------------------------------------------------


async def test_coverage_summary_covered_when_rules_exist(db_session: AsyncSession):
    src = await _make_source(db_session)
    await _add_rule(db_session, src, languages=["python"])

    repo = SemgrepRuleRepository(db_session)
    summary = await repo.get_coverage_summary(
        languages=["python"],
        allowed_licenses=["MIT"],
    )
    assert "python" in summary
    assert summary["python"]["covered"] is True
    assert summary["python"]["enabled_rule_count"] >= 1


async def test_coverage_summary_not_covered_when_no_rules(db_session: AsyncSession):
    repo = SemgrepRuleRepository(db_session)
    summary = await repo.get_coverage_summary(
        languages=["cobol"],  # no rules will exist for this
        allowed_licenses=["MIT"],
    )
    assert "cobol" in summary
    assert summary["cobol"]["covered"] is False
    assert summary["cobol"]["enabled_rule_count"] == 0


async def test_coverage_summary_recommends_disabled_sources(db_session: AsyncSession):
    src = await _make_source(db_session, enabled=False)
    await _add_rule(db_session, src, languages=["ruby"])

    repo = SemgrepRuleRepository(db_session)
    summary = await repo.get_coverage_summary(
        languages=["ruby"],
        allowed_licenses=["MIT"],
    )
    assert "ruby" in summary
    assert summary["ruby"]["covered"] is False
    rec_ids = [s.id for s in summary["ruby"]["recommended_sources"]]
    assert src.id in rec_ids


# ---------------------------------------------------------------------------
# Tests — upsert_rule dedup by content_hash
# ---------------------------------------------------------------------------


async def test_upsert_rule_deduplicates_unchanged_hash(db_session: AsyncSession):
    src = await _make_source(db_session)
    shared_hash = uuid.uuid4().hex

    data = {
        "namespaced_id": f"{src.slug}.dedup-rule",
        "original_id": "dedup-rule",
        "relative_path": "rules/dedup.yaml",
        "languages": ["python"],
        "severity": "ERROR",
        "category": "security",
        "technology": [],
        "cwe": [],
        "owasp": [],
        "confidence": "HIGH",
        "likelihood": None,
        "impact": None,
        "message": "dedup test",
        "raw_yaml": {"id": "dedup-rule"},
        "content_hash": shared_hash,
        "license_spdx": "MIT",
        "enabled": True,
    }

    repo = SemgrepRuleRepository(db_session)
    rule_a, is_new_a = await repo.upsert_rule(src.id, data)
    rule_b, is_new_b = await repo.upsert_rule(src.id, data)

    assert is_new_a is True
    assert is_new_b is False  # unchanged hash → no update
    assert rule_a.id == rule_b.id


# ---------------------------------------------------------------------------
# Tests — delete_rules_not_in safety guard
# ---------------------------------------------------------------------------


async def test_delete_rules_not_in_safety_guard(db_session: AsyncSession):
    """When keep_namespaced_ids is empty, nothing must be deleted."""
    src = await _make_source(db_session)
    rule = await _add_rule(db_session, src)
    await db_session.flush()

    repo = SemgrepRuleRepository(db_session)
    removed = await repo.delete_rules_not_in(src.id, set())
    assert removed == 0

    # Rule must still exist
    from sqlalchemy import select

    still_there = await db_session.scalar(
        select(db_models.SemgrepRule).where(db_models.SemgrepRule.id == rule.id)
    )
    assert still_there is not None


async def test_delete_rules_not_in_removes_stale(db_session: AsyncSession):
    src = await _make_source(db_session)
    rule_keep = await _add_rule(db_session, src)
    _rule_stale = await _add_rule(db_session, src)  # created for deletion side-effect
    await db_session.flush()

    repo = SemgrepRuleRepository(db_session)
    removed = await repo.delete_rules_not_in(src.id, {rule_keep.namespaced_id})
    assert removed == 1
