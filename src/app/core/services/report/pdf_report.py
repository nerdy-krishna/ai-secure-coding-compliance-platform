"""PDF findings-report generator — a paginated, print-oriented report.

This is a *dedicated print template*, distinct from `html_report.py`:
paged-media CSS (`@page`) drives a cover page, running header/footer with
page numbers, and per-finding page-break hints. WeasyPrint renders the
template HTML+CSS to a PDF byte string.

All finding-derived text is HTML-escaped — descriptions, titles, and
remediation originate from LLM output and uploaded code and are treated
as untrusted (see `core/schemas.py`).

PRD #96 / #98 / #101 / #102: print-tuned on-brand palette, plus the
scan-metadata block, executive summary, risk-score panel, models &
pipeline section, per-finding provenance, and triage-aware layout.
"""

from __future__ import annotations

from app.api.v1.models import AnalysisResultDetailResponse
from app.core.services.report._common import (
    PALETTE,
    _e,
    affected_lines,
    build_report_data,
    provenance_label,
    render_compact_findings,
    render_exec_summary,
    render_metadata_block,
    render_models_section,
    render_risk_panel,
    severity_color,
    severity_text_color,
)

_P = PALETTE

# Paged-media stylesheet. `@page` rules give the running header/footer
# and page numbers; the first page (the cover) suppresses the header.
# Shares the class names emitted by `_common.render_*` so the enriched
# sections render identically to the HTML report, with print sizing.
_PRINT_STYLE = f"""
@page {{
  size: A4;
  margin: 2.2cm 1.8cm 2cm 1.8cm;
  @top-left {{ content: "SCCAP — Security Scan Report"; font-size: 8.5px;
    color: {_P["fg_subtle"]}; }}
  @top-right {{ content: string(doc-project); font-size: 8.5px;
    color: {_P["fg_subtle"]}; }}
  @bottom-right {{ content: "Page " counter(page) " of " counter(pages);
    font-size: 8.5px; color: {_P["fg_subtle"]}; }}
}}
@page :first {{ @top-left {{ content: none }} @top-right {{ content: none }} }}
* {{ box-sizing: border-box; }}
body {{ font-family: "DejaVu Sans", sans-serif; color: {_P["fg"]};
  font-size: 10.5px; line-height: 1.5; }}
.doc-project {{ string-set: doc-project content(); position: absolute;
  left: -9999px; }}
.cover {{ page-break-after: always; padding-top: 4cm; }}
.cover .brand {{ display: flex; align-items: center; gap: 8px;
  margin-bottom: 26px; }}
.cover .brand .mark {{ width: 24px; height: 24px; border-radius: 6px;
  background: {_P["accent"]}; color: #fff; font-weight: 800;
  font-size: 13px; text-align: center; line-height: 24px; }}
.cover .brand .name {{ font-size: 11px; font-weight: 700;
  color: {_P["fg"]}; }}
.cover h1 {{ font-size: 30px; margin: 0 0 6px; color: {_P["fg"]}; }}
.cover .project {{ font-size: 18px; color: {_P["fg_muted"]};
  margin: 0 0 24px; }}
.cover .cmeta {{ font-size: 11px; color: {_P["fg_muted"]}; }}
.cover .cmeta div {{ margin-bottom: 3px; }}
.cover .cmeta b {{ color: {_P["fg"]}; }}
h2.section {{ font-size: 14px; border-bottom: 2px solid {_P["accent"]};
  padding-bottom: 4px; margin: 18px 0 10px; color: {_P["fg"]};
  page-break-after: avoid; }}
.muted {{ color: {_P["fg_muted"]}; }}
/* Scan-metadata block */
.metablock {{ display: flex; flex-wrap: wrap; border: 1px solid {_P["border"]};
  border-radius: 6px; overflow: hidden; }}
.meta-cell {{ width: 50%; background: {_P["surface"]}; padding: 6px 10px;
  display: flex; justify-content: space-between; gap: 10px; font-size: 9.5px;
  border-bottom: 1px solid {_P["border"]}; }}
.meta-cell .k {{ color: {_P["fg_subtle"]}; }}
.meta-cell .v {{ color: {_P["fg"]}; font-weight: 700; text-align: right; }}
/* Executive summary */
.exec {{ background: {_P["bg_soft"]}; border: 1px solid {_P["border"]};
  border-radius: 6px; padding: 10px 12px; font-size: 10px; margin: 0; }}
/* Risk panel */
.riskpanel {{ background: {_P["surface"]}; border: 1px solid {_P["border"]};
  border-radius: 6px; padding: 12px 14px; }}
.risk-scores {{ display: flex; gap: 30px; margin-bottom: 9px; }}
.risk-score {{ display: flex; flex-direction: column; }}
.risk-score .rs-num {{ font-size: 24px; font-weight: 800;
  color: {_P["accent"]}; }}
.risk-score.raw .rs-num {{ color: {_P["fg_subtle"]}; }}
.risk-score .rs-cap {{ font-size: 8px; color: {_P["fg_muted"]};
  text-transform: uppercase; letter-spacing: .04em; }}
.resolved {{ font-size: 9px; color: {_P["fg_muted"]}; margin-top: 8px; }}
/* Models & pipeline */
.models {{ display: flex; flex-wrap: wrap; gap: 8px; }}
.model-card {{ width: 48%; background: {_P["surface"]};
  border: 1px solid {_P["border"]}; border-radius: 6px; padding: 8px 10px;
  page-break-inside: avoid; }}
.model-cat {{ font-size: 7.5px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .05em; color: {_P["fg_subtle"]}; }}
.model-name {{ font-size: 10.5px; font-weight: 700; color: {_P["fg"]}; }}
.model-meta {{ font-size: 8.5px; color: {_P["fg_muted"]};
  font-family: "DejaVu Sans Mono", monospace; }}
.model-stat {{ font-size: 8.5px; color: {_P["fg_muted"]}; margin-top: 3px; }}
/* Counts + chips */
.counts {{ margin-top: 4px; }}
.count {{ display: inline-block; border-radius: 5px; padding: 3px 9px;
  font-size: 9px; font-weight: 700; margin-right: 5px; }}
/* Finding card */
.finding {{ page-break-inside: avoid; background: {_P["surface"]};
  border: 1px solid {_P["border"]}; border-radius: 6px;
  padding: 12px 14px; margin-bottom: 10px; }}
.finding h3 {{ font-size: 12px; margin: 0 0 4px; color: {_P["fg"]}; }}
.sev {{ display: inline-block; font-size: 8.5px; font-weight: 700;
  padding: 1.5px 7px; border-radius: 4px; margin-right: 6px; }}
.loc {{ font-family: "DejaVu Sans Mono", monospace; font-size: 9px;
  color: {_P["fg_muted"]}; }}
.prov {{ font-size: 8.5px; color: {_P["fg_subtle"]}; margin: 3px 0; }}
.label {{ font-size: 8.5px; font-weight: 700; text-transform: uppercase;
  color: {_P["fg_subtle"]}; letter-spacing: .05em; margin: 8px 0 2px; }}
.body {{ white-space: pre-wrap; overflow-wrap: anywhere; color: {_P["fg"]}; }}
pre {{ background: {_P["bg_soft"]}; border: 1px solid {_P["border"]};
  border-radius: 5px; padding: 7px 9px; font-size: 8.5px;
  font-family: "DejaVu Sans Mono", monospace; white-space: pre-wrap;
  overflow-wrap: anywhere; }}
.also {{ font-family: "DejaVu Sans Mono", monospace; font-size: 9px;
  color: {_P["fg_subtle"]}; margin-top: 6px; }}
.empty {{ color: {_P["fg_muted"]}; }}
/* Compact disposition lists */
.compact {{ list-style: none; margin: 0; padding: 0; }}
.cf-row {{ background: {_P["surface"]}; border: 1px solid {_P["border"]};
  border-radius: 5px; padding: 6px 9px; margin-bottom: 5px; font-size: 9px;
  page-break-inside: avoid; }}
.cf-title {{ font-weight: 700; color: {_P["fg"]}; }}
.cf-loc {{ font-family: "DejaVu Sans Mono", monospace; font-size: 8px;
  color: {_P["fg_muted"]}; }}
.cf-note {{ display: block; margin-top: 3px; color: {_P["fg_muted"]}; }}
"""


def _print_html(result: AnalysisResultDetailResponse) -> str:
    """Build the print-oriented HTML document WeasyPrint renders."""
    data = build_report_data(result)
    project = _e(data.project)

    if data.active:
        cards = "".join(_finding_card(f) for f in data.active)
    else:
        cards = '<p class="empty">No active findings for this scan.</p>'

    body = (
        '<h2 class="section">Scan metadata</h2>'
        + render_metadata_block(data)
        + render_exec_summary(data)
        + render_risk_panel(data)
        + render_models_section(data)
        + f'<h2 class="section">Active findings ({len(data.active)})</h2>'
        + cards
        + render_compact_findings("Remediated", data.remediated)
        + render_compact_findings("Risk Accepted", data.risk_accepted)
    )

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
  <div class="cmeta">
    <div><b>Scan type:</b> {_e(data.scan_type)}</div>
    <div><b>Findings:</b> {data.total_findings}</div>
    <div><b>Risk score:</b> {data.active_score:.1f} / 10 (active)
      &middot; {data.raw_score:.1f} / 10 (pre-triage)</div>
    <div><b>Generated:</b> {_e(data.generated)}</div>
  </div>
</section>
{body}
</body></html>"""


def _finding_card(finding) -> str:
    sev = finding.severity or "Informational"
    color = severity_color(sev)
    sev_fg = severity_text_color(sev)
    cvss = (
        f" &middot; CVSS {finding.cvss_score}" if finding.cvss_score is not None else ""
    )
    cwe = f" &middot; {_e(finding.cwe)}" if finding.cwe else ""
    prov = provenance_label(finding)
    prov_row = f'<div class="prov">Detected by {_e(prov)}</div>' if prov else ""
    snippet_row = (
        f'<div class="label">Vulnerable code</div>'
        f"<pre>{_e(finding.vulnerable_snippet)}</pre>"
        if finding.vulnerable_snippet
        else ""
    )
    lines = affected_lines(finding)
    also = (
        f'<div class="also">also affects: '
        f"{', '.join('line ' + str(n) for n in lines)}</div>"
        if lines
        else ""
    )
    agents = ", ".join(finding.corroborating_agents or [])
    agents_row = (
        f'<div class="label">Corroborated by</div><div class="body">{_e(agents)}</div>'
        if agents
        else ""
    )
    return f"""<div class="finding">
  <h3><span class="sev" style="background:{color};color:{sev_fg}">{_e(sev)}</span>{_e(finding.title)}</h3>
  <div class="loc">{_e(finding.file_path)}:{finding.line_number}{cvss}{cwe}</div>
  {prov_row}
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
