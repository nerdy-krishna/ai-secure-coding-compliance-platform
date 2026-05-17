"""Findings-report generators (#67) — HTML and CSV.

Pure, deterministic tests: a fixed `AnalysisResultDetailResponse`
fixture in, a rendered report out. No DB, no LLM.
"""

from __future__ import annotations

import csv
import io
import uuid

import pytest

from app.api.v1.models import (
    AnalysisResultDetailResponse,
    SubmittedFileReportItem,
    SummaryReportResponse,
    VulnerabilityFindingResponse,
)
from app.core.services.report import generate_report
from app.core.services.report.csv_report import render_csv
from app.core.services.report.html_report import render_html


def _finding(**overrides) -> VulnerabilityFindingResponse:
    base = dict(
        id=1,
        file_path="app.py",
        title="SQL injection",
        cwe=None,
        description="Untrusted input concatenated into a query.",
        severity="High",
        line_number=42,
        remediation="Use parameterised queries.",
        confidence="High",
        references=[],
    )
    base.update(overrides)
    return VulnerabilityFindingResponse(**base)


def _result(findings) -> AnalysisResultDetailResponse:
    project_id = uuid.uuid4()
    return AnalysisResultDetailResponse(
        status="COMPLETED",
        project_id=project_id,
        project_name="demo",
        summary_report=SummaryReportResponse(
            submission_id=uuid.uuid4(),
            project_id=project_id,
            project_name="demo",
            selected_frameworks=["asvs"],
            files_analyzed=[
                SubmittedFileReportItem(file_path="app.py", findings=findings),
            ],
        ),
    )


def test_csv_has_one_row_per_finding_with_expected_columns():
    result = _result([_finding(id=1), _finding(id=2, title="XSS", line_number=9)])
    rows = list(csv.DictReader(io.StringIO(render_csv(result))))
    assert len(rows) == 2
    assert set(rows[0]) >= {
        "file_path",
        "line_number",
        "severity",
        "cvss_score",
        "title",
        "description",
        "remediation",
        "corroborating_agents",
        "affected_lines",
    }
    assert {r["title"] for r in rows} == {"SQL injection", "XSS"}


def test_csv_collapses_affected_locations_into_one_column():
    result = _result(
        [
            _finding(
                affected_locations=[
                    {"line_number": 7, "snippet": "a"},
                    {"line_number": 19, "snippet": "b"},
                ]
            )
        ]
    )
    rows = list(csv.DictReader(io.StringIO(render_csv(result))))
    assert len(rows) == 1
    assert rows[0]["affected_lines"] == "7; 19"


def test_html_is_self_contained_and_lists_every_finding():
    result = _result(
        [_finding(title="UNIQUE-SQLI"), _finding(id=2, title="UNIQUE-XSS")]
    )
    doc = render_html(result)
    assert doc.startswith("<!DOCTYPE html>")
    assert "<style>" in doc  # inline CSS
    assert "<link" not in doc and "<script" not in doc  # no external assets
    assert "UNIQUE-SQLI" in doc and "UNIQUE-XSS" in doc


def test_html_escapes_finding_text():
    result = _result([_finding(title="<img src=x onerror=alert(1)>")])
    doc = render_html(result)
    assert "<img src=x" not in doc
    assert "&lt;img src=x" in doc


def test_generate_report_dispatches_and_rejects_unknown_format():
    result = _result([_finding()])
    html_artifact = generate_report(result, "html")
    assert html_artifact.media_type.startswith("text/html")
    assert html_artifact.filename.endswith(".html")

    csv_artifact = generate_report(result, "csv")
    assert csv_artifact.media_type.startswith("text/csv")
    assert csv_artifact.filename.endswith(".csv")

    with pytest.raises(ValueError):
        generate_report(result, "xml")


def test_pdf_artifact_is_a_non_empty_valid_pdf():
    """The PDF generator produces a non-empty artifact whose bytes carry
    the PDF magic header. WeasyPrint (+ pango) must be installed."""
    result = _result([_finding(title="PDFI-SQLI"), _finding(id=2, title="PDFI-XSS")])
    artifact = generate_report(result, "pdf")
    assert artifact.media_type == "application/pdf"
    assert artifact.filename.endswith(".pdf")
    assert isinstance(artifact.content, bytes)
    assert artifact.content.startswith(b"%PDF-")
    assert len(artifact.content) > 1_000  # a real rendered document
    assert artifact.content.rstrip().endswith(b"%%EOF")


def test_pdf_renders_with_no_findings():
    """An empty scan still produces a valid PDF (cover + empty section)."""
    artifact = generate_report(_result([]), "pdf")
    assert artifact.content.startswith(b"%PDF-")
