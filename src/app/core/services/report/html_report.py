"""HTML findings-report generator — a self-contained, styled report.

The output is a single standalone `.html` document (inline CSS, no
external assets) so it opens in any browser and can be printed to PDF.
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

# Print-tuned restyle (PRD #96 / #98) — the website's light / variant-A
# palette, shared via `_common.PALETTE`. White surfaces, SCCAP teal
# accent, app severity colors.
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
.counts {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 18px 0 30px; }}
.count {{ border-radius: 7px; padding: 6px 13px; font-size: 13px;
  font-weight: 700; }}
.finding {{ background: {_P['surface']}; border: 1px solid {_P['border']};
  border-radius: 10px; padding: 20px 22px; margin-bottom: 14px; }}
.finding h2 {{ font-size: 16px; margin: 0 0 6px; color: {_P['fg']}; }}
.sev {{ display: inline-block; font-size: 11px; font-weight: 700;
  padding: 2px 9px; border-radius: 5px; margin-right: 8px;
  vertical-align: middle; }}
.loc {{ font-family: ui-monospace, Menlo, monospace; font-size: 12px;
  color: {_P['fg_muted']}; }}
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
.foot {{ color: {_P['fg_subtle']}; font-size: 11px; margin-top: 36px;
  text-align: center; border-top: 1px solid {_P['border']};
  padding-top: 16px; }}
"""


def _e(value: object) -> str:
    """HTML-escape any value; empty string for None."""
    return html.escape(str(value)) if value is not None else ""


def render_html(result: AnalysisResultDetailResponse) -> str:
    """Render the scan's findings as a standalone HTML document."""
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
<style>{_STYLE}</style></head><body><div class="wrap">
<div class="brand"><span class="mark">S</span>
  <span class="name">SCCAP &middot; Secure Coding &amp; Compliance</span></div>
<h1>Security scan report</h1>
<div class="meta">
  <b>{project}</b> &middot; {scan_type} scan &middot;
  {len(findings)} finding{"" if len(findings) == 1 else "s"}<br>
  Frameworks: {frameworks or "&mdash;"} &middot; Generated {generated}
</div>
<div class="counts">{count_chips}</div>
{cards}
<div class="foot">Generated by SCCAP &middot; {generated}</div>
</div></body></html>"""


def _finding_card(finding) -> str:
    sev = finding.severity or "Informational"
    color = severity_color(sev)
    sev_fg = severity_text_color(sev)
    cvss = (
        f" &middot; CVSS {finding.cvss_score}" if finding.cvss_score is not None else ""
    )
    cwe = f" &middot; {_e(finding.cwe)}" if finding.cwe else ""
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
  <h2><span class="sev" style="background:{color};color:{sev_fg}">{_e(sev)}</span>{_e(finding.title)}</h2>
  <div class="loc">{_e(finding.file_path)}:{finding.line_number}{cvss}{cwe}</div>
  <div class="label">Description</div>
  <div class="body">{_e(finding.description)}</div>
  {snippet_row}
  {also}
  <div class="label">Remediation</div>
  <div class="body">{_e(finding.remediation)}</div>
  {fix_row}
  {agents_row}
</div>"""
