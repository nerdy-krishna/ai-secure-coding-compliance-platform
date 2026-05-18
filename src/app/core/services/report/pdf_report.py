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
from app.core.services.report._common import (
    PALETTE,
    affected_lines,
    collect_findings,
    severity_color,
    severity_text_color,
)

_P = PALETTE

# Paged-media stylesheet (PRD #96 / #98 restyle). `@page` rules give the
# running header/footer and page numbers; the first page (the cover)
# suppresses the header. Print-tuned with the website's light /
# variant-A palette shared via `_common.PALETTE`. Fonts stay DejaVu —
# the families WeasyPrint reliably embeds.
_PRINT_STYLE = f"""
@page {{
  size: A4;
  margin: 2.2cm 1.8cm 2cm 1.8cm;
  @top-left {{ content: "SCCAP — Security Scan Report"; font-size: 8.5px;
    color: {_P['fg_subtle']}; }}
  @top-right {{ content: string(doc-project); font-size: 8.5px;
    color: {_P['fg_subtle']}; }}
  @bottom-right {{ content: "Page " counter(page) " of " counter(pages);
    font-size: 8.5px; color: {_P['fg_subtle']}; }}
}}
@page :first {{ @top-left {{ content: none }} @top-right {{ content: none }} }}
* {{ box-sizing: border-box; }}
body {{ font-family: "DejaVu Sans", sans-serif; color: {_P['fg']};
  font-size: 10.5px; line-height: 1.5; }}
.doc-project {{ string-set: doc-project content(); position: absolute;
  left: -9999px; }}
.cover {{ page-break-after: always; padding-top: 4cm; }}
.cover .brand {{ display: flex; align-items: center; gap: 8px;
  margin-bottom: 26px; }}
.cover .brand .mark {{ width: 24px; height: 24px; border-radius: 6px;
  background: {_P['accent']}; color: #fff; font-weight: 800;
  font-size: 13px; text-align: center; line-height: 24px; }}
.cover .brand .name {{ font-size: 11px; font-weight: 700;
  color: {_P['fg']}; }}
.cover h1 {{ font-size: 30px; margin: 0 0 6px; color: {_P['fg']}; }}
.cover .project {{ font-size: 18px; color: {_P['fg_muted']};
  margin: 0 0 24px; }}
.cover .meta {{ font-size: 11px; color: {_P['fg_muted']}; }}
.cover .meta div {{ margin-bottom: 3px; }}
.cover .meta b {{ color: {_P['fg']}; }}
.counts {{ margin-top: 22px; }}
.count {{ display: inline-block; border-radius: 5px; padding: 4px 11px;
  font-size: 10px; font-weight: 700; margin-right: 6px; }}
h2.section {{ font-size: 15px; border-bottom: 2px solid {_P['accent']};
  padding-bottom: 4px; margin: 0 0 14px; color: {_P['fg']}; }}
.finding {{ page-break-inside: avoid; background: {_P['surface']};
  border: 1px solid {_P['border']}; border-radius: 7px;
  padding: 12px 14px; margin-bottom: 12px; }}
.finding h3 {{ font-size: 12.5px; margin: 0 0 5px; color: {_P['fg']}; }}
.sev {{ display: inline-block; font-size: 8.5px; font-weight: 700;
  padding: 1.5px 7px; border-radius: 4px; margin-right: 6px; }}
.loc {{ font-family: "DejaVu Sans Mono", monospace; font-size: 9px;
  color: {_P['fg_muted']}; margin-bottom: 6px; }}
.label {{ font-size: 8.5px; font-weight: 700; text-transform: uppercase;
  color: {_P['fg_subtle']}; letter-spacing: .05em; margin: 8px 0 2px; }}
.body {{ white-space: pre-wrap; overflow-wrap: anywhere; color: {_P['fg']}; }}
pre {{ background: {_P['bg_soft']}; border: 1px solid {_P['border']};
  border-radius: 5px; padding: 7px 9px; font-size: 8.5px;
  font-family: "DejaVu Sans Mono", monospace; white-space: pre-wrap;
  overflow-wrap: anywhere; }}
.also {{ font-family: "DejaVu Sans Mono", monospace; font-size: 9px;
  color: {_P['fg_subtle']}; margin-top: 6px; }}
.empty {{ color: {_P['fg_muted']}; }}
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
        f'<span class="count" style="background:{severity_color(sev)};'
        f'color:{severity_text_color(sev)}">'
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
  <div class="brand"><span class="mark">S</span>
    <span class="name">SCCAP &middot; Secure Coding &amp; Compliance</span></div>
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
    color = severity_color(sev)
    sev_fg = severity_text_color(sev)
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
  <h3><span class="sev" style="background:{color};color:{sev_fg}">{_e(sev)}</span>{_e(finding.title)}</h3>
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
