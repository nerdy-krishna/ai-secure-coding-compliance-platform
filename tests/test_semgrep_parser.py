# tests/test_semgrep_parser.py
"""Unit tests for the Semgrep rule YAML parser.

Pure function tests — no DB, no network. Uses the fixture YAMLs under
tests/fixtures/semgrep_rules/.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock


from app.core.services.semgrep_ingestion.parser import parse_rule_file

FIXTURES = Path(__file__).parent / "fixtures" / "semgrep_rules"


def _make_source(slug: str = "test-source") -> MagicMock:
    src = MagicMock()
    src.slug = slug
    src.license_spdx = "MIT"
    return src


# ---------------------------------------------------------------------------
# Parser extracts expected fields
# ---------------------------------------------------------------------------


def test_python_sql_injection_languages():
    src = _make_source()
    rules = parse_rule_file(FIXTURES / "python_sql_injection.yaml", src, FIXTURES)
    assert len(rules) == 1
    r = rules[0]
    assert "python" in r["languages"]
    assert r["severity"] == "ERROR"
    assert r["namespaced_id"] == "test-source.python-sql-injection"
    assert r["original_id"] == "python-sql-injection"


def test_cwe_extracted_correctly():
    src = _make_source()
    rules = parse_rule_file(FIXTURES / "python_sql_injection.yaml", src, FIXTURES)
    r = rules[0]
    assert any("CWE-89" in c for c in r["cwe"])


def test_owasp_extracted():
    src = _make_source()
    rules = parse_rule_file(FIXTURES / "python_sql_injection.yaml", src, FIXTURES)
    r = rules[0]
    assert any("A03" in o for o in r["owasp"])


def test_javascript_multi_language():
    src = _make_source()
    rules = parse_rule_file(FIXTURES / "javascript_xss.yaml", src, FIXTURES)
    assert len(rules) == 1
    r = rules[0]
    assert "javascript" in r["languages"]
    assert "typescript" in r["languages"]
    assert r["severity"] == "ERROR"


def test_technology_extracted():
    src = _make_source()
    rules = parse_rule_file(FIXTURES / "python_shell_injection.yaml", src, FIXTURES)
    r = rules[0]
    assert "python" in r["technology"]


def test_java_impact_likelihood():
    src = _make_source()
    rules = parse_rule_file(FIXTURES / "java_path_traversal.yaml", src, FIXTURES)
    r = rules[0]
    assert r["impact"] == "HIGH"
    assert r["likelihood"] == "MEDIUM"


def test_license_comes_from_source():
    src = _make_source()
    src.license_spdx = "Apache-2.0"
    rules = parse_rule_file(FIXTURES / "go_hardcoded_secret.yaml", src, FIXTURES)
    r = rules[0]
    assert r["license_spdx"] == "Apache-2.0"


def test_content_hash_is_stable():
    """The content hash must be deterministic across multiple parse calls."""
    src = _make_source()
    rules_a = parse_rule_file(FIXTURES / "python_sql_injection.yaml", src, FIXTURES)
    rules_b = parse_rule_file(FIXTURES / "python_sql_injection.yaml", src, FIXTURES)
    assert rules_a[0]["content_hash"] == rules_b[0]["content_hash"]


def test_content_hash_changes_when_rule_changes(tmp_path):
    """Mutating the rule YAML must produce a different content hash."""
    import yaml

    original = FIXTURES / "python_sql_injection.yaml"
    content = yaml.safe_load(original.read_text())

    copy_a = tmp_path / "rule_a.yaml"
    copy_a.write_text(original.read_text())

    content["rules"][0]["message"] = "Modified message"
    copy_b = tmp_path / "rule_b.yaml"
    copy_b.write_text(yaml.safe_dump(content))

    src = _make_source()
    hash_a = parse_rule_file(copy_a, src, tmp_path)[0]["content_hash"]
    hash_b = parse_rule_file(copy_b, src, tmp_path)[0]["content_hash"]
    assert hash_a != hash_b


def test_test_yaml_files_are_skipped(tmp_path):
    """Files ending in .test.yaml must produce 0 rules (skipped by caller,
    not the parser itself), but let's confirm the parser still works on them
    — the skip happens in the sync_service walker, not inside parse_rule_file.
    This test verifies the file IS parseable (no crash).
    """
    import shutil

    test_file = tmp_path / "rule.test.yaml"
    shutil.copy(FIXTURES / "python_sql_injection.yaml", test_file)
    src = _make_source()
    # parse_rule_file itself doesn't skip test files; the walker does.
    # Confirm it parses normally.
    rules = parse_rule_file(test_file, src, tmp_path)
    assert len(rules) == 1


def test_go_rule_parsed():
    src = _make_source()
    rules = parse_rule_file(FIXTURES / "go_hardcoded_secret.yaml", src, FIXTURES)
    assert len(rules) == 1
    r = rules[0]
    assert "go" in r["languages"]
    assert any("CWE-798" in c for c in r["cwe"])


def test_namespaced_id_uses_slug():
    src = _make_source(slug="my-custom-source")
    rules = parse_rule_file(FIXTURES / "python_sql_injection.yaml", src, FIXTURES)
    assert rules[0]["namespaced_id"].startswith("my-custom-source.")


def test_message_is_extracted():
    src = _make_source()
    rules = parse_rule_file(FIXTURES / "python_sql_injection.yaml", src, FIXTURES)
    assert "SQL injection" in rules[0]["message"]
