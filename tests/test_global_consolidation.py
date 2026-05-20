from app.core.schemas import VulnerabilityFinding
from app.infrastructure.workflows.nodes.global_consolidate import _merge_cluster


def _finding(path: str, title: str = "Missing CSP") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title=title,
        description="desc",
        severity="Medium",
        line_number=1,
        remediation="Add CSP header",
        confidence="High",
        file_path=path,
        cwe="CWE-693",
    )


def test_global_merge_preserves_multifile_affected_locations():
    merged = _merge_cluster(
        [_finding("templates/a.html"), _finding("templates/b.html")]
    )
    assert merged.file_path == "templates/a.html"
    assert {loc.file_path for loc in merged.affected_locations or []} == {
        "templates/a.html",
        "templates/b.html",
    }
