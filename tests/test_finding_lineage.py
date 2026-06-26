"""Test the Finding Lineage graph builder with duck-typed findings."""

from __future__ import annotations

from app.core.services.scan.lineage import build_lineage_from_findings, resolve_domain


# ── Domain mapping ───────────────────────────────────────────────────


def test_resolve_domain_from_agent_name():
    assert resolve_domain("AsvsAccessControlAgent", None) == "Access Control"
    assert resolve_domain("AsvsApiSecurityAgent", None) == "API Security"
    assert resolve_domain("AsvsErrorHandlingAgent", None) == "Error Handling"
    assert resolve_domain("AsvsFileHandlingAgent", None) == "File Handling"


def test_resolve_domain_from_cwe():
    assert resolve_domain(None, "CWE-22") == "Access Control"
    assert resolve_domain(None, "CWE-79") == "Input Validation"
    assert resolve_domain(None, "CWE-89") == "Input Validation"
    assert resolve_domain(None, "CWE-312") == "Cryptography"
    assert resolve_domain(None, "CWE-295") == "Cryptography"
    assert resolve_domain(None, "CWE-287") == "Authentication"
    assert resolve_domain(None, "CWE-798") == "Authentication"
    assert resolve_domain(None, "CWE-209") == "Error Handling"
    assert resolve_domain(None, "CWE-918") == "API Security"


def test_resolve_domain_from_sast_source():
    assert resolve_domain("semgrep", None) == "Static Analysis"
    assert resolve_domain("bandit", None) == "Static Analysis"
    assert resolve_domain("gitleaks", None) == "Secrets Management"
    assert resolve_domain("osv", None) == "Dependency Security"


def test_resolve_domain_agent_wins_over_sast():
    assert resolve_domain("AsvsAccessControlAgent", "CWE-22") == "Access Control"


def test_resolve_domain_cwe_wins_over_default():
    assert resolve_domain("semgrep", "CWE-22") == "Access Control"


def test_resolve_domain_fallback_to_uncategorized():
    assert resolve_domain(None, None) == "Uncategorized"
    assert resolve_domain("unknown-tool", None) == "Uncategorized"


# ── Lineage graph builder ────────────────────────────────────────────


class _DummyFinding:
    """A duck-typed finding with only the fields lineage.py actually reads."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_build_empty():
    graph = build_lineage_from_findings(
        sast_findings=[],
        raw_llm_findings=[],
        consolidated_findings=[],
    )
    assert graph["nodes"] == []
    assert graph["edges"] == []
    assert graph["lineage_quality"] == "inferred"


def test_build_small_scan_with_sast_and_llm():
    sast = [
        _DummyFinding(
            source="semgrep",
            file_path="src/app.py",
            cwe="CWE-22",
            title="Path traversal",
            severity="High",
            agent_name=None,
            id=1,
        ),
    ]
    raw_llm = [
        _DummyFinding(
            source="AsvsAccessControlAgent",
            file_path="src/app.py",
            cwe=None,
            title="IDOR via cookie",
            severity="High",
            agent_name="AsvsAccessControlAgent",
            id=2,
        ),
        _DummyFinding(
            source="AsvsErrorHandlingAgent",
            file_path="src/app.py",
            cwe=None,
            title="Info leak in error",
            severity="Medium",
            agent_name="AsvsErrorHandlingAgent",
            id=3,
        ),
    ]
    consolidated = [
        _DummyFinding(
            title="Root finding",
            severity="High",
            id=4,
        ),
    ]

    graph = build_lineage_from_findings(
        sast_findings=sast,
        raw_llm_findings=raw_llm,
        consolidated_findings=consolidated,
    )

    assert len(graph["nodes"]) > 0
    # edges may be empty in inferred mode without flow_map
    assert graph["lineage_quality"] == "inferred"
    assert len(graph["warnings"]) > 0

    # Check column coverage
    columns = {n["column"] for n in graph["nodes"]}
    assert 0 in columns, "Files column missing"
    assert 1 in columns, "Detection Sources column missing"
    assert 2 in columns, "Domains column missing"
    assert 3 in columns, "Consolidation column missing"
    assert 4 in columns, "Outputs column missing"


def test_build_preserves_node_count_cap():
    many_sast = [
        _DummyFinding(
            source="semgrep",
            file_path=f"src/f{i}.py",
            cwe="CWE-79",
            title=f"XSS {i}",
            severity="High",
            agent_name=None,
            id=i,
        )
        for i in range(50)
    ]
    graph = build_lineage_from_findings(
        sast_findings=many_sast,
        raw_llm_findings=[],
        consolidated_findings=[],
        max_nodes=10,
    )
    assert len(graph["nodes"]) <= 10
