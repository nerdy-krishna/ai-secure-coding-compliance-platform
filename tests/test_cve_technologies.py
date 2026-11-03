"""Technologies, references and the research step.

Three things an operator expects that the first version did not do: record what a
non-HTTP asset runs, give the model something to research a CVE *from*, and keep the
counts honest when one asset yields several candidate verdicts.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.assets import matcher
from app.assets import models as am
from app.assets import verification


def technology(product: str, version: str | None, category: str = "database") -> SimpleNamespace:
    return SimpleNamespace(
        asset_id=uuid.uuid4(),
        product=product,
        version=version,
        category=category,
        source="manual",
        confidence="exact",
    )


def nginx_range() -> list[am.CveAffected]:
    return [
        am.CveAffected(
            cve_id="CVE-2021-23017",
            kind="cpe",
            vendor="nginx",
            product="nginx",
            version_start_incl="0.6.18",
            version_end_excl="1.20.1",
        )
    ]


def test_database_without_an_endpoint_is_matched():
    """A managed database has a version and no URL; that must still match."""
    finding = matcher._technology_match(
        "CVE-2021-23017", technology("nginx", "1.18.0", "web"), nginx_range()
    )

    assert finding is not None
    assert finding.verdict == am.UNDETERMINED
    assert finding.evidence["version"] == "1.18.0"
    assert finding.evidence["needs_version"] is False


def test_technology_with_unknown_version_is_a_candidate():
    finding = matcher._technology_match(
        "CVE-2021-23017", technology("nginx", None, "web"), nginx_range()
    )

    assert finding is not None
    assert finding.evidence["needs_version"] is True
    assert "obtain the version" in finding.reason


def test_technology_outside_the_range_is_not_a_candidate():
    assert (
        matcher._technology_match(
            "CVE-2021-23017", technology("nginx", "1.25.3", "web"), nginx_range()
        )
        is None
    )


def test_duplicate_candidates_keep_the_one_with_a_version():
    """An endpoint and a technology row can describe the same product."""
    asset_id = uuid.uuid4()
    weak = matcher.Finding(
        asset_id=asset_id,
        cve_id="CVE-2021-23017",
        verdict=am.UNDETERMINED,
        confidence="low",
        basis=am.BASIS_OBSERVED,
        reason="no version",
        evidence={"product": "nginx", "version": None},
    )
    strong = matcher.Finding(
        asset_id=asset_id,
        cve_id="CVE-2021-23017",
        verdict=am.UNDETERMINED,
        confidence="medium",
        basis=am.BASIS_OBSERVED,
        reason="1.18.0",
        evidence={"product": "nginx", "version": "1.18.0"},
    )

    assert matcher._better(weak, strong) is strong
    assert matcher._better(strong, weak) is strong


def test_references_render_for_the_prompt():
    cve = SimpleNamespace(
        id="CVE-2021-23017",
        references=[
            {"url": "https://nginx.org/advisory", "tags": ["Vendor Advisory"]},
            {"url": "https://example.test/poc", "tags": ["Exploit"]},
        ],
    )

    rendered = verification._render_references(cve)

    assert "https://nginx.org/advisory" in rendered
    assert "Exploit" in rendered
    assert "No advisory" not in rendered


def test_missing_references_say_so():
    rendered = verification._render_references(SimpleNamespace(id="CVE-1", references=None))
    assert "No advisory or exploit references" in rendered


def test_research_block_reaches_the_design_prompt():
    research = verification.CveResearch(
        mechanism="off-by-one in the DNS resolver",
        detection_signals=["version below 1.20.1"],
        patched_version="1.20.1",
        reference_insights=["advisory names 1.20.1"],
        testability_note="a version check decides it",
    )

    rendered = verification._render_research(research)

    assert "off-by-one" in rendered
    assert "1.20.1" in rendered
    assert "version check decides it" in rendered


def test_usage_context_is_attributed_to_the_asset():
    """Usage attribution needs a UUID and an asset, or every call is dropped."""
    asset_id = uuid.uuid4()

    context = verification._usage_context("CVE-2021-23017", "cve.research", asset_id)

    assert context.operation_kind == "cve"
    assert context.asset_id == asset_id
    uuid.UUID(context.operation_id)  # must parse
