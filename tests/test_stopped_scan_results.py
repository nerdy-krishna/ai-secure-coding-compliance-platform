"""A scan stopped at the prescan gate must still show what the scanners found.

The deterministic findings are persisted before the gate opens, so stopping is a
choice about the *LLM phase*, not about discarding the work already done. These
tests cover the two pieces that make that visible: the source-line anchor every
finding carries, and the results payload built when no `scan.summary` exists.
"""

from __future__ import annotations

import datetime
import uuid

from app.core.services.scan.query import ScanQueryService
from app.infrastructure.database import models as db_models
from app.shared.lib.files import source_line_at


def test_source_line_at() -> None:
    body = "import os\n\nAWS_KEY = 'AKIA...'\n"
    assert source_line_at(body, 3) == "AWS_KEY = 'AKIA...'"
    assert source_line_at(body, 1) == "import os"
    assert source_line_at(body, 99) is None
    assert source_line_at(body, 0) is None
    assert source_line_at(None, 3) is None
    assert source_line_at("a\n   \n", 2) is None


def _scan_with(findings: list[db_models.Finding]) -> db_models.Scan:
    now = datetime.datetime.now(datetime.timezone.utc)
    scan = db_models.Scan(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        scan_type="AUDIT",
        status="BLOCKED_USER_DECLINE",
        frameworks=[],
        summary=None,
        created_at=now,
    )
    scan.project = None
    scan.updated_at = now
    scan.completed_at = None
    scan.findings = findings
    return scan


def _finding(
    index: int, path: str, line: int, severity: str, source: str, snippet: str | None = None
) -> db_models.Finding:
    return db_models.Finding(
        id=index,
        file_path=path,
        line_number=line,
        title=f"{source} finding",
        description="detail",
        severity=severity,
        remediation="",
        confidence="HIGH",
        source=source,
        vulnerable_snippet=snippet,
        disposition="open",
        references=[],
        is_applied_in_remediation=False,
    )


def test_stopped_scan_renders_its_findings() -> None:
    scan = _scan_with(
        [
            _finding(1, "src/config.py", 3, "CRITICAL", "gitleaks"),
            _finding(2, "src/app.py", 1, "MEDIUM", "bandit", snippet="hashlib.md5(x)"),
        ]
    )
    code = {"src/config.py": "import os\n\nAWS_KEY = 'AKIA...'\n"}

    report = ScanQueryService._deterministic_only_report(scan, code)

    assert report.summary.total_findings_count == 2
    assert [item.file_path for item in report.files_analyzed] == [
        "src/app.py",
        "src/config.py",
    ]
    by_path = {item.file_path: item.findings for item in report.files_analyzed}
    assert by_path["src/app.py"][0].vulnerable_snippet == "hashlib.md5(x)"
    # A row persisted without a snippet still gets a code anchor.
    assert by_path["src/config.py"][0].vulnerable_snippet == "AWS_KEY = 'AKIA...'"
    assert report.summary.severity_counts.CRITICAL == 1
    assert report.summary.severity_counts.MEDIUM == 1
    assert report.overall_risk_score.score > 0


def test_stopped_scan_with_no_source_map_still_renders() -> None:
    scan = _scan_with([_finding(1, "src/app.py", 1, "HIGH", "semgrep")])
    report = ScanQueryService._deterministic_only_report(scan, {})
    assert report.files_analyzed[0].findings[0].file_path == "src/app.py"
    assert report.files_analyzed[0].findings[0].vulnerable_snippet is None
