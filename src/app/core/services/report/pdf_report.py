"""PDF findings-report generator — a paginated, print-oriented report.

This is a *dedicated print template*, distinct from `html_report.py`:
paged-media CSS (`@page`) drives a cover/summary page, running
header/footer with page numbers, and per-finding page-break hints.
WeasyPrint renders the template HTML+CSS to a PDF byte string.

All finding-derived text is HTML-escaped — descriptions, titles, and
remediation originate from LLM output and uploaded code and are treated
as untrusted (see `core/schemas.py`).
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone

from app.api.v1.models import AnalysisResultDetailResponse
from app.core.services.report._common import affected_lines, collect_findings

_SEV_COLOR = {
    "Critical": "#b4232a",
    "High": "#c2410c",
    "Medium": "#b45309",
    "Low": "#3f6212",
    "Informational": "#475569",
}

# Paged-media stylesheet. `@page` rules give the running header/footer
# and page numbers; the first page (the cover) suppresses the header.
_PRINT_STYLE = """
@page {
  size: A4;
  margin: 2.2cm 1.8cm 2cm 1.8cm;
  @top-left { content: "SCCAP — Security Scan Report"; font-size: 8.5px;
    color: #999; }
  @top-right { content: string(doc-project); font-size: 8.5px;
    color: #999; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages);
    font-size: 8.5px; color: #999; }
}
@page :first { @top-left { content: none } @top-right { content: none } }
* { box-sizing: border-box; }
body { font-family: "DejaVu Sans", sans-serif; color: #1a1a1a;
  font-size: 10.5px; line-height: 1.5; }
.doc-project { string-set: doc-project content(); position: absolute;
  left: -9999px; }
.cover { page-break-after: always; padding-top: 5cm; }
.cover h1 { font-size: 30px; margin: 0 0 6px; }
.cover .project { font-size: 18px; color: #333; margin: 0 0 24px; }
.cover .meta { font-size: 11px; color: #555; }
.cover .meta div { margin-bottom: 3px; }
.counts { margin-top: 22px; }
.count { display: inline-block; border-radius: 4px; padding: 4px 10px;
  font-size: 10px; font-weight: 700; color: #fff; margin-right: 6px; }
h2.section { font-size: 15px; border-bottom: 2px solid #1a1a1a;
  padding-bottom: 4px; margin: 0 0 14px; }
.finding { page-break-inside: avoid; border: 1px solid #ddd;
  border-radius: 5px; padding: 12px 14px; margin-bottom: 12px; }
.finding h3 { font-size: 12.5px; margin: 0 0 5px; }
.sev { display: inline-block; font-size: 8.5px; font-weight: 700;
  padding: 1.5px 6px; border-radius: 3px; color: #fff; margin-right: 6px; }
.loc { font-family: "DejaVu Sans Mono", monospace; font-size: 9px;
  color: #555; margin-bottom: 6px; }
.label { font-size: 8.5px; font-weight: 700; text-transform: uppercase;
  color: #999; letter-spacing: .05em; margin: 8px 0 2px; }
.body { white-space: pre-wrap; overflow-wrap: anywhere; }
pre { background: #f6f6f4; border: 1px solid #e2e2dd; border-radius: 4px;
  padding: 7px 9px; font-size: 8.5px; font-family: "DejaVu Sans Mono",
  monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
.also { font-family: "DejaVu Sans Mono", monospace; font-size: 9px;
  color: #777; margin-top: 6px; }
.empty { color: #555; }
"""


def _e(value: object) -> str:
    """HTML-escape any value; empty string for None."""
    return html.escape(str(value)) if value is not None else ""


def _print_html(result: AnalysisResultDetailResponse) -> str:
    """Build the print-oriented HTML document WeasyPrint renders."""
    report = result.summary_report
    findings = collect_findings(result)

    project = _e(report.project_name if report else result.project_name)
    scan_type = _e(report.scan_type if report else "audit")
    frameworks = _e(", ".join(report.selected_frameworks)) if report else ""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    counts = Counter(f.severity for f in findings)
    count_chips = "".join(
        f'<span class="count" style="background:{_SEV_COLOR.get(sev, "#475569")}">'
        f"{_e(sev)}: {counts[sev]}</span>"
        for sev in ("Critical", "High", "Medium", "Low", "Informational")
        if counts.get(sev)
    )

    if findings:
        cards = "".join(_finding_card(f) for f in findings)
    else:
        cards = '<p class="empty">No findings were reported for this scan.</p>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Security scan report — {project}</title>
<style>{_PRINT_STYLE}</style></head><body>
<span class="doc-project">{project}</span>
<section class="cover">
  <h1>Security Scan Report</h1>
  <div class="project">{project}</div>
  <div class="meta">
    <div><b>Scan type:</b> {scan_type}</div>
    <div><b>Frameworks:</b> {frameworks or "&mdash;"}</div>
    <div><b>Findings:</b> {len(findings)}</div>
    <div><b>Generated:</b> {generated}</div>
  </div>
  <div class="counts">{count_chips}</div>
</section>
<h2 class="section">Findings</h2>
{cards}
</body></html>"""


def _finding_card(finding) -> str:
    sev = finding.severity or "Informational"
    color = _SEV_COLOR.get(sev, "#475569")
    cvss = (
        f" &middot; CVSS {finding.cvss_score}" if finding.cvss_score is not None else ""
    )
    cwe = f" &middot; {_e(finding.cwe)}" if finding.cwe else ""
    snippet_row = (
        f'<div class="label">Vulnerable code</div>'
        f"<pre>{_e(finding.vulnerable_snippet)}</pre>"
        if finding.vulnerable_snippet
        else ""
    )
    lines = affected_lines(finding)
    also = (
        f'<div class="also">also affects: '
        f'{", ".join("line " + str(n) for n in lines)}</div>'
        if lines
        else ""
    )
    agents = ", ".join(finding.corroborating_agents or [])
    agents_row = (
        f'<div class="label">Corroborated by</div>'
        f'<div class="body">{_e(agents)}</div>'
        if agents
        else ""
    )
    return f"""<div class="finding">
  <h3><span class="sev" style="background:{color}">{_e(sev)}</span>{_e(finding.title)}</h3>
  <div class="loc">{_e(finding.file_path)}:{finding.line_number}{cvss}{cwe}</div>
  <div class="label">Description</div>
  <div class="body">{_e(finding.description)}</div>
  {snippet_row}
  {also}
  <div class="label">Remediation</div>
  <div class="body">{_e(finding.remediation)}</div>
  {agents_row}
</div>"""


def render_pdf(result: AnalysisResultDetailResponse) -> bytes:
    """Render the scan's findings as a paginated PDF byte string."""
    # Imported lazily so the report package stays importable (HTML/CSV
    # paths, tests) on hosts without WeasyPrint's pango system libs.
    from weasyprint import HTML

    document = _print_html(result)
    pdf = HTML(string=document).write_pdf()
    if pdf is None:  # pragma: no cover — WeasyPrint returns bytes here
        raise RuntimeError("WeasyPrint produced no PDF output")
    return pdf
