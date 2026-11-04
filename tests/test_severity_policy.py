"""Severity policy: what a finding is worth when nobody told us.

The failure this encodes: every ZAP alert with a CWE outside our table scored 9.1
critical, so a missing CSP header, a timestamp in a JavaScript bundle and a user-agent
fuzzer all ranked alongside SQL injection — 68 "criticals" from one site.
"""

from __future__ import annotations

from app.pentest import cvss
from app.pentest.findings import _extract
from app.pentest.tools.zap_tool import aggregate_alerts


def severity(cwe: str, reported: str, title: str = "finding") -> str:
    return cvss.derive(
        {"title": title, "cwe": cwe, "severity": reported, "evidence": {"url": "https://x/"}}
    )[2]


def test_unknown_weakness_does_not_become_critical():
    assert severity("CWE-9999", "medium") == "medium"
    assert severity("", "medium") == "medium"
    assert severity("CWE-0", "medium") == "medium"


def test_unknown_weakness_cannot_exceed_the_ceiling():
    """A tool claiming 'high' for an unmapped CWE is capped, not trusted blindly."""
    assert severity("CWE-9999", "high") == "medium"


def test_informational_stays_informational():
    assert severity("CWE-9999", "informational") == "info"
    assert severity("CWE-9999", "Low") == "low"


def test_known_impact_weakness_keeps_its_score():
    """SQL injection is genuinely critical; the policy must not flatten real findings."""
    assert severity("CWE-89", "critical") == "critical"
    assert severity("CWE-79", "medium") == "medium"


def test_defence_gaps_score_below_injection():
    csp = cvss.derive({"title": "CSP missing", "cwe": "CWE-693", "severity": "medium"})[1]
    sqli = cvss.derive({"title": "SQLi", "cwe": "CWE-89", "severity": "critical"})[1]

    assert csp < 4.0
    assert sqli >= 9.0


def test_zap_alerts_of_the_same_shape_collapse():
    alerts = [
        {"name": "User Agent Fuzzer", "cwe": 0, "risk": "0", "url": f"https://t/static/js/c{i}.js"}
        for i in range(20)
    ]
    alerts += [
        {"name": "Timestamp Disclosure - Unix", "cwe": 497, "risk": "0", "url": "https://t/static/js/main.js"}
    ]

    aggregated = aggregate_alerts(alerts)

    assert len(aggregated) == 2
    fuzzer = next(item for item in aggregated if item["name"] == "User Agent Fuzzer")
    assert fuzzer["instances"] == 20
    assert len(fuzzer["urls"]) <= 8
    assert aggregated[0]["instances"] >= aggregated[1]["instances"], "loudest first"


def test_different_paths_are_not_merged():
    alerts = [
        {"name": "X", "cwe": 1, "risk": "1", "url": "https://t/admin/login"},
        {"name": "X", "cwe": 1, "risk": "1", "url": "https://t/api/users"},
    ]

    assert len(aggregate_alerts(alerts)) == 2


def test_a_zap_alert_set_produces_non_critical_findings():
    """The end-to-end shape of the bug: a ZAP page of 'criticals' that are not."""
    output = {
        "alerts": [
            {
                "name": "Content Security Policy (CSP) Header Not Set",
                "severity": "medium",
                "cwe": 693,
                "url": "https://t.example.com/",
                "instances": 1,
            },
            {
                "name": "Timestamp Disclosure - Unix",
                "severity": "info",
                "cwe": 497,
                "url": "https://t.example.com/static/js/main.js",
                "instances": 12,
            },
            {
                "name": "User Agent Fuzzer",
                "severity": "info",
                "cwe": 0,
                "url": "https://t.example.com/",
                "instances": 20,
            },
        ]
    }

    findings = _extract("zap_scan", output)
    scored = [cvss.apply(dict(finding))["severity"] for finding in findings]

    assert "critical" not in scored
    assert set(scored) <= {"medium", "low", "info"}
