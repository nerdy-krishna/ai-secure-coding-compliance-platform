# tests/test_finding_references.py
#
# VulnerabilityFinding.references sanitiser. An LLM agent sometimes emits a
# bare identifier (e.g. "CWE-22") in `references`; the field used to raise a
# ValidationError, which aborted the whole agent invocation. The sanitiser now
# coerces / drops instead of rejecting.

from app.core.schemas import VulnerabilityFinding


def _finding(references):
    return VulnerabilityFinding(
        title="t",
        description="d",
        severity="High",
        line_number=1,
        remediation="r",
        confidence="Medium",
        file_path="a.c",
        references=references,
    )


def test_bare_cwe_token_is_coerced_to_mitre_url():
    f = _finding(["CWE-22"])
    assert f.references == ["https://cwe.mitre.org/data/definitions/22.html"]


def test_cwe_coercion_is_case_insensitive():
    assert _finding(["cwe-79"]).references == [
        "https://cwe.mitre.org/data/definitions/79.html"
    ]


def test_valid_urls_are_kept():
    urls = ["https://example.com/a", "http://example.org/b"]
    assert _finding(urls).references == urls


def test_mixed_list_coerces_keeps_and_drops():
    f = _finding(["CWE-89", "https://ok.example/x", "just some text", ""])
    assert f.references == [
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://ok.example/x",
    ]


def test_over_long_url_is_dropped_not_raised():
    long_url = "https://example.com/" + "x" * 2100
    # Previously raised ValidationError; now silently dropped.
    assert _finding([long_url, "CWE-1"]).references == [
        "https://cwe.mitre.org/data/definitions/1.html"
    ]


def test_list_is_capped_at_twenty():
    f = _finding([f"https://example.com/{i}" for i in range(30)])
    assert len(f.references) == 20


def test_empty_and_default_references():
    assert _finding([]).references == []
    f = VulnerabilityFinding(
        title="t",
        description="d",
        severity="High",
        line_number=1,
        remediation="r",
        confidence="Medium",
        file_path="a.c",
    )
    assert f.references == []


def test_non_url_non_cwe_does_not_raise():
    # The whole point: a junk reference must never abort finding construction.
    f = _finding(["see the docs", "CWE-bogus", "ftp://nope"])
    assert f.references == []
