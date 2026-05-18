"""HTML findings-report generator — a self-contained, styled report.

The output is a single standalone `.html` document (inline CSS, no
external assets) so it opens in any browser and can be printed to PDF.
All finding-derived text is HTML-escaped — descriptions, titles, and
remediation originate from LLM output and uploaded code and are treated
as untrusted (see `core/schemas.py`).

PRD #96 / #98 / #101 / #102: print-tuned on-brand palette, plus the
scan-metadata block, executive summary, risk-score panel, models &
pipeline section, per-finding provenance, and triage-aware layout
(active findings as full cards; remediated / risk-accepted compact;
false positives counted only).
"""

from __future__ import annotations

from app.api.v1.models import AnalysisResultDetailResponse
from app.core.services.report._common import (
    PALETTE,
    ReportData,
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

# Print-tuned restyle (#98) + enriched sections (#101 / #102) — the
# website's light / variant-A palette, shared via `_common.PALETTE`.
_STYLE = f"""
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue",
  sans-serif; margin: 0; background: {_P['bg']}; color: {_P['fg']};
  line-height: 1.55; }}
.wrap {{ max-width: 940px; margin: 0 auto; padding: 36px 28px 72px; }}
.brand {{ display: flex; align-items: center; gap: 9px; margin-bottom: 22px; }}
.brand .mark {{ width: 26px; height: 26px; border-radius: 7px;
  background: {_P['accent']}; color: #fff; font-weight: 800; font-size: 13px;
  display: flex; align-items: center; justify-content: center; }}
.brand .name {{ font-size: 13px; font-weight: 700; letter-spacing: .02em;
  color: {_P['fg']}; }}
h1 {{ font-size: 23px; margin: 0 0 4px; color: {_P['fg']}; }}
.meta {{ color: {_P['fg_muted']}; font-size: 13px; margin-bottom: 22px; }}
.meta b {{ color: {_P['fg']}; }}
h2.section {{ font-size: 15px; color: {_P['fg']};
  border-bottom: 2px solid {_P['accent']}; padding-bottom: 5px;
  margin: 30px 0 14px; }}
.muted {{ color: {_P['fg_muted']}; font-size: 13px; }}
/* Scan-metadata block */
.metablock {{ display: grid; grid-template-columns: 1fr 1fr;
  gap: 1px; background: {_P['border']}; border: 1px solid {_P['border']};
  border-radius: 9px; overflow: hidden; margin-bottom: 6px; }}
.meta-cell {{ background: {_P['surface']}; padding: 9px 13px;
  display: flex; justify-content: space-between; gap: 12px;
  font-size: 12.5px; }}
.meta-cell .k {{ color: {_P['fg_subtle']}; }}
.meta-cell .v {{ color: {_P['fg']}; font-weight: 600; text-align: right; }}
/* Executive summary */
.exec {{ background: {_P['surface']}; border: 1px solid {_P['border']};
  border-radius: 9px; padding: 16px 18px; font-size: 13.5px;
  color: {_P['fg']}; margin: 0; }}
/* Risk panel */
.riskpanel {{ background: {_P['surface']}; border: 1px solid {_P['border']};
  border-radius: 9px; padding: 18px 20px; }}
.risk-scores {{ display: flex; gap: 28px; margin-bottom: 14px; }}
.risk-score {{ display: flex; flex-direction: column; }}
.risk-score .rs-num {{ font-size: 30px; font-weight: 800;
  color: {_P['accent']}; line-height: 1; }}
.risk-score.raw .rs-num {{ color: {_P['fg_subtle']}; }}
.risk-score .rs-cap {{ font-size: 11px; color: {_P['fg_muted']};
  text-transform: uppercase; letter-spacing: .04em; margin-top: 5px; }}
.resolved {{ font-size: 12px; color: {_P['fg_muted']}; margin-top: 12px; }}
/* Models & pipeline */
.models {{ display: flex; flex-wrap: wrap; gap: 12px; }}
.model-card {{ background: {_P['surface']}; border: 1px solid {_P['border']};
  border-radius: 9px; padding: 13px 15px; min-width: 220px; flex: 1; }}
.model-cat {{ font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .05em; color: {_P['fg_subtle']}; }}
.model-name {{ font-size: 13.5px; font-weight: 600; color: {_P['fg']};
  margin-top: 2px; }}
.model-meta {{ font-size: 11.5px; color: {_P['fg_muted']};
  font-family: ui-monospace, Menlo, monospace; }}
.model-stat {{ font-size: 11.5px; color: {_P['fg_muted']}; margin-top: 6px; }}
/* Counts + chips */
.counts {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 6px 0 0; }}
.count {{ border-radius: 7px; padding: 5px 12px; font-size: 12.5px;
  font-weight: 700; }}
/* Finding card */
.finding {{ background: {_P['surface']}; border: 1px solid {_P['border']};
  border-radius: 10px; padding: 20px 22px; margin-bottom: 14px; }}
.finding h3 {{ font-size: 16px; margin: 0 0 6px; color: {_P['fg']}; }}
.sev {{ display: inline-block; font-size: 11px; font-weight: 700;
  padding: 2px 9px; border-radius: 5px; margin-right: 8px;
  vertical-align: middle; }}
.loc {{ font-family: ui-monospace, Menlo, monospace; font-size: 12px;
  color: {_P['fg_muted']}; }}
.prov {{ font-size: 11.5px; color: {_P['fg_subtle']}; margin-top: 3px; }}
.label {{ font-size: 11px; font-weight: 700; text-transform: uppercase;
  color: {_P['fg_subtle']}; letter-spacing: .05em; margin: 13px 0 3px; }}
.body {{ font-size: 13.5px; white-space: pre-wrap; overflow-wrap: anywhere;
  color: {_P['fg']}; }}
pre {{ background: {_P['bg_soft']}; border: 1px solid {_P['border']};
  border-radius: 7px; padding: 11px 13px; font-size: 12px; overflow-x: auto;
  white-space: pre-wrap; overflow-wrap: anywhere;
  font-family: ui-monospace, Menlo, monospace; }}
.also {{ font-family: ui-monospace, Menlo, monospace; font-size: 12px;
  color: {_P['fg_subtle']}; margin-top: 8px; }}
.empty {{ color: {_P['fg_muted']}; font-size: 14px; }}
/* Compact disposition lists */
.compact {{ list-style: none; margin: 0; padding: 0; }}
.cf-row {{ background: {_P['surface']}; border: 1px solid {_P['border']};
  border-radius: 7px; padding: 9px 12px; margin-bottom: 7px;
  font-size: 12.5px; }}
.cf-title {{ font-weight: 600; color: {_P['fg']}; }}
.cf-loc {{ font-family: ui-monospace, Menlo, monospace; font-size: 11px;
  color: {_P['fg_muted']}; }}
.cf-note {{ display: block; margin-top: 4px; color: {_P['fg_muted']}; }}
.foot {{ color: {_P['fg_subtle']}; font-size: 11px; margin-top: 36px;
  text-align: center; border-top: 1px solid {_P['border']};
  padding-top: 16px; }}
"""


def render_html(result: AnalysisResultDetailResponse) -> str:
    """Render the scan's findings as a standalone HTML document."""
    data = build_report_data(result)
    project = _e(data.project)

    if data.active:
        cards = "".join(_finding_card(f) for f in data.active)
    else:
        cards = '<p class="empty">No active findings for this scan.</p>'

    body = (
        render_metadata_block(data)
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
<style>{_STYLE}</style></head><body><div class="wrap">
<div class="brand"><span class="mark">S</span>
  <span class="name">SCCAP &middot; Secure Coding &amp; Compliance</span></div>
<h1>Security scan report</h1>
<div class="meta">
  <b>{project}</b> &middot; {_e(data.scan_type)} scan &middot;
  {data.total_findings} finding{"" if data.total_findings == 1 else "s"}
  &middot; Generated {_e(data.generated)}
</div>
{body}
<div class="foot">Generated by SCCAP &middot; {_e(data.generated)}</div>
</div></body></html>"""


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
    agents = ", ".join(finding.corroborating_agents or [])
    agents_row = (
        f'<div class="label">Corroborated by</div>'
        f'<div class="body">{_e(agents)}</div>'
        if agents
        else ""
    )
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
    fix_row = ""
    if finding.fixes and isinstance(finding.fixes, dict) and finding.fixes.get("code"):
        fix_row = (
            f'<div class="label">Suggested fix</div>'
            f'<pre>{_e(finding.fixes.get("code"))}</pre>'
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
  {fix_row}
  {agents_row}
</div>"""


# Imported by `_common`-less callers / tests that introspect the module.
__all__ = ["render_html", "ReportData"]
