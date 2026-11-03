"""CVE matching: versions, ranges, and the difference between a hint and a verdict."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.assets import matcher
from app.assets import models as am
from app.assets.versions import compare, in_range, pairs, product_matches, upstream


def test_versions_compare_numerically_not_lexically():
    assert compare("1.10.0", "1.9.9") == 1
    assert compare("1.2", "1.2.0") == 0
    assert compare("2.0.0-rc1", "2.0.0") == -1
    assert compare("1.0.0", "1.0.1") == -1


def test_distro_packaging_is_stripped():
    # The upstream version is what CVE ranges describe.
    assert upstream("1:1.2.3-4ubuntu5") == "1.2.3"
    assert upstream("3.0.11-2.el9") == "3.0.11"
    # A prerelease suffix is part of the upstream version and must survive.
    assert upstream("2.0.0-rc1") == "2.0.0-rc1"
    assert in_range("1:1.2.3-4ubuntu5", start_incl="1.2.0", end_excl="1.3.0")


def test_range_bounds():
    assert in_range("1.4.9", start_incl="1.0.0", end_excl="1.5.0")
    assert not in_range("1.5.0", start_incl="1.0.0", end_excl="1.5.0")
    assert in_range("1.5.0", start_incl="1.0.0", end_incl="1.5.0")
    assert not in_range("0.9.0", start_incl="1.0.0")
    assert in_range("9.9.9", exact=["9.9.9"])


def test_unknown_version_is_never_in_range():
    """Silence must not read as safety: no version means no match, not 'unaffected'."""
    assert not in_range(None, start_incl="1.0.0")
    assert not in_range("", start_incl="1.0.0")


def test_products_match_by_name_not_by_banner_noise():
    assert product_matches("nginx", "nginx/1.18.0")
    assert product_matches("openssl", "Open_SSL 3.0.1")
    assert product_matches("lodash", "lodash")
    assert not product_matches("nginx", "apache")


def test_declared_match_is_applicable_with_high_confidence():
    dependency = SimpleNamespace(
        asset_id=uuid.uuid4(),
        ecosystem="npm",
        package="lodash",
        version="4.17.20",
        source="scan",
        scan_id=None,
    )
    ranges = [
        am.CveAffected(
            cve_id="CVE-2021-23337",
            kind="ecosystem",
            ecosystem="npm",
            package="lodash",
            version_end_excl="4.17.21",
        )
    ]

    finding = matcher._declared_match("CVE-2021-23337", dependency, ranges)

    assert finding is not None
    assert finding.verdict == am.APPLICABLE
    assert finding.basis == am.BASIS_DECLARED
    assert finding.confidence == "high"
    assert finding.evidence["version"] == "4.17.20"


def test_declared_match_outside_range_is_not_a_candidate():
    dependency = SimpleNamespace(
        asset_id=uuid.uuid4(), ecosystem="npm", package="lodash", version="4.17.21",
        source="scan", scan_id=None,
    )
    ranges = [
        am.CveAffected(
            cve_id="CVE-2021-23337",
            kind="ecosystem",
            ecosystem="npm",
            package="lodash",
            version_end_excl="4.17.21",
        )
    ]
    assert matcher._declared_match("CVE-2021-23337", dependency, ranges) is None


def test_observed_match_is_only_undetermined():
    """A banner is a hypothesis; the verdict says so instead of claiming a vuln."""
    service = SimpleNamespace(
        asset_id=uuid.uuid4(),
        host="app.example.com",
        port=443,
        path=None,
        product="nginx",
        version="1.18.0",
        banner="nginx/1.18.0",
        confidence="heuristic",
    )
    ranges = [
        am.CveAffected(
            cve_id="CVE-2021-23017",
            kind="cpe",
            vendor="nginx",
            product="nginx",
            version_start_incl="0.6.18",
            version_end_excl="1.20.1",
        )
    ]

    finding = matcher._observed_match("CVE-2021-23017", service, ranges)

    assert finding is not None
    assert finding.verdict == am.UNDETERMINED
    assert finding.basis == am.BASIS_OBSERVED
    assert finding.confidence == "medium"
    assert "only" not in finding.reason.lower() or "cannot confirm" in finding.reason.lower()


def test_merged_server_header_yields_every_product():
    """`BaseHTTP/0.6 Python/3.12.16, nginx/1.18.0` carries two products, not one."""
    found = pairs("BaseHTTP/0.6 Python/3.12.16, nginx/1.18.0")

    assert ("nginx", "1.18.0") in [(name.lower(), version) for name, version in found]
    assert all(name.lower() != "http" for name, _ in found)


def test_match_uses_the_product_the_cve_is_about_in_a_merged_banner():
    """The nginx CVE must match nginx's version, not the proxy's."""
    service = SimpleNamespace(
        asset_id=uuid.uuid4(),
        host="10.0.0.5",
        port=8080,
        path=None,
        product="BaseHTTP",
        version="0.6",
        banner="BaseHTTP/0.6 Python/3.12.16, nginx/1.18.0",
        confidence="heuristic",
    )
    ranges = [
        am.CveAffected(
            cve_id="CVE-2021-23017",
            kind="cpe",
            vendor="nginx",
            product="nginx",
            version_start_incl="0.6.18",
            version_end_excl="1.20.1",
        )
    ]

    finding = matcher._observed_match("CVE-2021-23017", service, ranges)

    assert finding is not None
    assert finding.evidence["product"].lower() == "nginx"
    assert finding.evidence["version"] == "1.18.0"


def test_product_without_a_version_is_a_candidate_not_silence():
    """A bare IP with a known product must produce work, not "nothing found"."""
    service = SimpleNamespace(
        asset_id=uuid.uuid4(),
        host="10.0.0.5",
        port=443,
        path=None,
        product="nginx",
        version=None,
        banner="nginx",
        confidence="heuristic",
    )
    ranges = [
        am.CveAffected(
            cve_id="CVE-2021-23017",
            kind="cpe",
            vendor="nginx",
            product="nginx",
            version_start_incl="0.6.18",
            version_end_excl="1.20.1",
        )
    ]

    finding = matcher._observed_match("CVE-2021-23017", service, ranges)

    assert finding is not None, "a matching product with no version must not be ignored"
    assert finding.verdict == am.UNDETERMINED
    assert finding.evidence["needs_version"] is True
    assert "obtain the version" in finding.reason


def test_ecosystem_rows_never_match_a_banner():
    service = SimpleNamespace(
        asset_id=uuid.uuid4(), host="app.example.com", port=443, path=None,
        product="lodash", version="4.17.20", banner=None, confidence="heuristic",
    )
    ranges = [
        am.CveAffected(
            cve_id="CVE-2021-23337", kind="ecosystem", ecosystem="npm",
            package="lodash", version_end_excl="4.17.21",
        )
    ]
    assert matcher._observed_match("CVE-2021-23337", service, ranges) is None


def test_only_observed_undetermined_rows_are_worth_a_probe():
    assert matcher.needs_verification(
        SimpleNamespace(basis=am.BASIS_OBSERVED, verdict=am.UNDETERMINED)
    )
    assert not matcher.needs_verification(
        SimpleNamespace(basis=am.BASIS_DECLARED, verdict=am.APPLICABLE)
    )
    assert not matcher.needs_verification(
        SimpleNamespace(basis=am.BASIS_PROBE, verdict=am.APPLICABLE)
    )
