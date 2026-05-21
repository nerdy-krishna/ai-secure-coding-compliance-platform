"""Shared helpers for the findings-report generators.

Includes the report palette (PRD #96 / #98): reports are standalone
documents and cannot reference the website's live CSS variables, so the
values of the light / variant-A design tokens (see
``secure-code-ui/src/app/styles/tokens.css``) are inlined here once and
shared by the HTML and PDF generators. Print-tuned — white surfaces, the
app's accent and severity colors, no dark theme.
"""

from __future__ import annotations

import html
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.api.v1.models import (
    AnalysisResultDetailResponse,
    ConsolidationStats,
    LLMUsageItem,
    VulnerabilityFindingResponse,
)
from app.shared.lib.risk_score import compute_cvss_aggregate, scoreable_findings

# Severity sort order — Critical first, Informational last.
SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}

# The website's light / variant-A design tokens, inlined for reports.
PALETTE: Dict[str, str] = {
    "bg": "#fbfaf7",  # warm paper page background
    "surface": "#ffffff",  # cards
    "bg_soft": "#f5f3ee",  # code blocks, soft fills
    "bg_inset": "#efece5",
    "border": "#e7e3d8",
    "border_strong": "#d6d1c2",
    "fg": "#1a1b20",
    "fg_muted": "#5b5e68",
    "fg_subtle": "#878a94",
    "accent": "#0ea5a4",  # teal
    "accent_weak": "#e0f4f3",
    "primary": "#4f46e5",  # indigo
    "primary_weak": "#eef0ff",
    "primary_strong": "#3730a3",
}

# Severity → chip background, from the app's risk tokens.
SEVERITY_COLORS: Dict[str, str] = {
    "Critical": "#e11d48",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#06b6d4",
    "Informational": "#6366f1",
}

# Severities whose chip needs dark text for legible print contrast
# (yellow / cyan wash out under white text).
_SEVERITY_DARK_TEXT = {"Medium", "Low"}


def severity_color(severity: str) -> str:
    """Chip background color for a severity label."""
    return SEVERITY_COLORS.get(severity, PALETTE["fg_muted"])


def severity_text_color(severity: str) -> str:
    """Legible foreground for text drawn on a severity chip."""
    return PALETTE["fg"] if severity in _SEVERITY_DARK_TEXT else "#ffffff"


def collect_findings(
    result: AnalysisResultDetailResponse,
) -> List[VulnerabilityFindingResponse]:
    """Flatten every finding across the scan's analysed files, sorted by
    severity then file then line — the order a reviewer reads them in."""
    report = result.summary_report
    if report is None:
        return []
    findings: List[VulnerabilityFindingResponse] = []
    for file_item in report.files_analyzed:
        findings.extend(file_item.findings)
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            f.file_path,
            f.line_number,
        )
    )
    return findings


def affected_lines(finding: VulnerabilityFindingResponse) -> List[int]:
    """The line numbers in a finding's `affected_locations`, if any."""
    out: List[int] = []
    for loc in finding.affected_locations or []:
        line = loc.get("line_number") if isinstance(loc, dict) else None
        if isinstance(line, int):
            out.append(line)
    return out


# ── Enriched-report content (PRD #96 / #101 / #102) ────────────────────
#
# `build_report_data` derives everything the enriched templates render
# from one scan result, so the HTML and PDF generators stay consistent.
# The shared `render_*` fragment builders below emit HTML with stable
# class names; each generator's stylesheet supplies its own sizing.

# Severities in display order.
SEVERITY_DISPLAY = ["Critical", "High", "Medium", "Low", "Informational"]

# Disposition value → human label (mirrors the app's triage vocabulary).
DISPOSITION_LABELS: Dict[str, str] = {
    "open": "Open",
    "confirmed": "Confirmed",
    "false_positive": "False Positive",
    "remediated": "Remediated",
    "risk_accepted": "Risk Accepted",
}


def _e(value: object) -> str:
    """HTML-escape any value; empty string for None. Finding-derived
    text is LLM-emitted from attacker-controlled code — always escape."""
    return html.escape(str(value)) if value is not None else ""


def disposition_label(value: Optional[str]) -> str:
    """Human label for a disposition value; defaults to Open."""
    return DISPOSITION_LABELS.get(value or "open", "Open")


@dataclass
class _ModelStat:
    """Per-LLM finding tally for the models & pipeline section."""

    count: int = 0
    sev: "Counter[str]" = field(default_factory=Counter)


@dataclass
class ReportData:
    """Everything the enriched report templates render, derived once
    from the scan result so HTML and PDF stay byte-consistent."""

    project: str
    scan_type: str
    frameworks: List[str]
    generated: str
    # Findings partitioned by triage disposition.
    active: List[VulnerabilityFindingResponse]  # open + confirmed
    remediated: List[VulnerabilityFindingResponse]
    risk_accepted: List[VulnerabilityFindingResponse]
    false_positive_count: int
    total_findings: int
    severity_counts: Dict[str, int]  # over active findings
    # Risk (#102): triage-adjusted vs pre-triage.
    active_score: float
    raw_score: float
    # Models & pipeline (#101).
    llms_used: List[LLMUsageItem]
    per_model: Dict[str, _ModelStat]  # llm name -> tally
    consolidation: Optional[ConsolidationStats]
    # Provenance (#101).
    osv_finding_count: int
    # Scan-metadata block (#101). `source` / `temperature` are the
    # submission settings surfaced in the report (PRD #96 follow-up).
    scan_id: str
    started: str
    completed: str
    file_count: int
    dual_llm: bool
    cross_file: bool
    source: str
    temperature: str
    exec_summary: str = field(default="")


def _fmt_ts(value: Optional[datetime]) -> str:
    """Format a timestamp as `YYYY-MM-DD HH:MM UTC`, or '' for None."""
    if value is None:
        return ""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _source_label(result: AnalysisResultDetailResponse) -> str:
    """Human label for how the scan's code was submitted."""
    source_type = getattr(result, "source_type", None)
    url = getattr(result, "repository_url", None)
    if source_type == "git":
        return f"Git repository ({url})" if url else "Git repository"
    if source_type == "archive":
        return "Archive upload (zip / rar)"
    if source_type == "upload":
        return "Direct file upload"
    # Pre-`source_type` scans: fall back to the project's repo URL.
    return f"Git repository ({url})" if url else "Uploaded files"


def _temperature_label(result: AnalysisResultDetailResponse) -> str:
    """Human label for the scan's LLM-temperature setting."""
    if getattr(result, "disable_temperature", False):
        return "Disabled — deterministic output"
    temps = getattr(result, "stage_temperatures", None)
    if temps:
        return " · ".join(f"{k}: {v}" for k, v in temps.items())
    return "Provider default"


def build_report_data(result: AnalysisResultDetailResponse) -> ReportData:
    """Derive the enriched-report content model from a scan result."""
    report = result.summary_report
    findings = collect_findings(result)

    project = (report.project_name if report else result.project_name) or "N/A"
    scan_type = (report.scan_type if report else "audit") or "audit"
    frameworks = list(report.selected_frameworks) if report else []

    active: List[VulnerabilityFindingResponse] = []
    remediated: List[VulnerabilityFindingResponse] = []
    risk_accepted: List[VulnerabilityFindingResponse] = []
    false_positive_count = 0
    for finding in findings:
        disposition = getattr(finding, "disposition", None) or "open"
        if disposition == "remediated":
            remediated.append(finding)
        elif disposition == "risk_accepted":
            risk_accepted.append(finding)
        elif disposition == "false_positive":
            false_positive_count += 1
        else:  # open / confirmed / anything unknown — treated as active
            active.append(finding)

    severity_counts = Counter(f.severity for f in active)

    active_score = compute_cvss_aggregate(scoreable_findings(findings))
    raw_score = compute_cvss_aggregate(findings)

    per_model: Dict[str, _ModelStat] = {}
    for finding in findings:
        for name in getattr(finding, "detected_by_llms", None) or []:
            slot = per_model.setdefault(name, _ModelStat())
            slot.count += 1
            slot.sev[finding.severity] += 1

    osv_finding_count = sum(1 for f in findings if getattr(f, "source", None) == "osv")

    scan_id = str(report.submission_id) if report else ""
    file_count = len(report.files_analyzed) if report else 0
    dual_llm = any(
        getattr(item, "category", "") == "2nd Analysis LLM" for item in result.llms_used
    )

    started_dt: Optional[datetime] = None
    completed_dt: Optional[datetime] = None
    if result.events:
        stamps = sorted(e.timestamp for e in result.events)
        started_dt, completed_dt = stamps[0], stamps[-1]
    elif report and report.analysis_timestamp:
        completed_dt = report.analysis_timestamp

    data = ReportData(
        project=project,
        scan_type=scan_type,
        frameworks=frameworks,
        generated=_fmt_ts(datetime.now(timezone.utc)),
        active=active,
        remediated=remediated,
        risk_accepted=risk_accepted,
        false_positive_count=false_positive_count,
        total_findings=len(findings),
        severity_counts=dict(severity_counts),
        active_score=active_score,
        raw_score=raw_score,
        llms_used=list(result.llms_used),
        per_model=per_model,
        consolidation=result.consolidation_stats,
        osv_finding_count=osv_finding_count,
        scan_id=scan_id,
        started=_fmt_ts(started_dt),
        completed=_fmt_ts(completed_dt),
        file_count=file_count,
        dual_llm=dual_llm,
        cross_file=bool(result.cross_file_validation),
        source=_source_label(result),
        temperature=_temperature_label(result),
    )
    data.exec_summary = _exec_summary(data)
    return data


def _exec_summary(data: ReportData) -> str:
    """A short prose paragraph summarising the scan outcome — built from
    the structured counts (the scan summary carries no narrative text)."""
    fw = ", ".join(data.frameworks) if data.frameworks else "no frameworks"
    sentences: List[str] = [
        f"This {data.scan_type.lower()} scan analysed {data.file_count} "
        f"file{'' if data.file_count == 1 else 's'} against {fw} and "
        f"surfaced {data.total_findings} "
        f"finding{'' if data.total_findings == 1 else 's'}."
    ]
    active_n = len(data.active)
    sev_bits = [
        f"{data.severity_counts[s]} {s.lower()}"
        for s in SEVERITY_DISPLAY
        if data.severity_counts.get(s)
    ]
    sev_text = (", ".join(sev_bits)) if sev_bits else "none"
    sentences.append(
        f"{active_n} remain active ({sev_text}); "
        f"{len(data.remediated)} remediated, "
        f"{len(data.risk_accepted)} risk-accepted, "
        f"{data.false_positive_count} false-positive."
    )
    sentences.append(
        f"The triage-adjusted risk score is {data.active_score:.1f} / 10 "
        f"(pre-triage {data.raw_score:.1f} / 10)."
    )
    return " ".join(sentences)


def render_metadata_block(data: ReportData) -> str:
    """The scan-provenance block (#101)."""
    rows = [
        ("Scan ID", data.scan_id or "—"),
        ("Scan type", data.scan_type),
        ("Source", data.source),
        ("Files analysed", str(data.file_count)),
        ("Frameworks", ", ".join(data.frameworks) or "—"),
        ("Temperature", data.temperature),
        ("Started", data.started or "—"),
        ("Completed", data.completed or "—"),
        ("Dual-LLM analysis", "Yes" if data.dual_llm else "No"),
        ("Cross-file validation", "Yes" if data.cross_file else "No"),
    ]
    cells = "".join(
        f'<div class="meta-cell"><span class="k">{_e(k)}</span>'
        f'<span class="v">{_e(v)}</span></div>'
        for k, v in rows
    )
    return f'<div class="metablock">{cells}</div>'


def render_exec_summary(data: ReportData) -> str:
    """The executive-summary paragraph (#101)."""
    return (
        '<h2 class="section">Executive summary</h2>'
        f'<p class="exec">{_e(data.exec_summary)}</p>'
    )


def render_risk_panel(data: ReportData) -> str:
    """The risk-score panel — active vs pre-triage raw (#102)."""
    chips = (
        "".join(
            f'<span class="count" style="background:{severity_color(s)};'
            f'color:{severity_text_color(s)}">{_e(s)}: {data.severity_counts[s]}'
            "</span>"
            for s in SEVERITY_DISPLAY
            if data.severity_counts.get(s)
        )
        or '<span class="muted">No active findings.</span>'
    )
    resolved = (
        f"{len(data.remediated)} remediated &middot; "
        f"{len(data.risk_accepted)} risk-accepted &middot; "
        f"{data.false_positive_count} false-positive"
    )
    return (
        '<h2 class="section">Risk score</h2>'
        '<div class="riskpanel">'
        '<div class="risk-scores">'
        f'<div class="risk-score"><span class="rs-num">'
        f"{data.active_score:.1f}</span>"
        '<span class="rs-cap">/ 10 &middot; active</span></div>'
        f'<div class="risk-score raw"><span class="rs-num">'
        f"{data.raw_score:.1f}</span>"
        '<span class="rs-cap">/ 10 &middot; pre-triage</span></div>'
        "</div>"
        f'<div class="counts">{chips}</div>'
        f'<div class="resolved">Resolved: {resolved}</div>'
        "</div>"
    )


def render_models_section(data: ReportData) -> str:
    """The models & pipeline section — per-role LLMs, per-model finding
    stats, and the consolidation tally (#101)."""
    if not data.llms_used:
        return ""
    cards = []
    for item in data.llms_used:
        stats = data.per_model.get(item.name)
        stat_line = ""
        if stats:
            sev_bits = " ".join(
                f"{s[0]}{stats.sev[s]}"  # e.g. C2 H1
                for s in SEVERITY_DISPLAY
                if stats.sev.get(s)
            )
            stat_line = (
                f'<div class="model-stat">{stats.count} '
                f"finding{'' if stats.count == 1 else 's'} detected"
                f"{(' &middot; ' + sev_bits) if sev_bits else ''}</div>"
            )
        consolidation_line = ""
        cs = data.consolidation
        if item.category == "Reasoning LLM" and cs and cs.raw_count:
            extra = ""
            if cs.merged_inputs or cs.dropped:
                extra = (
                    f" &middot; {cs.merged_inputs} merged &middot; {cs.dropped} dropped"
                )
            consolidation_line = (
                f'<div class="model-stat">Consolidation: {cs.raw_count} '
                f"raw &rarr; {cs.consolidated_count} kept{extra}</div>"
            )
        cards.append(
            f'<div class="model-card">'
            f'<div class="model-cat">{_e(item.category)}</div>'
            f'<div class="model-name">{_e(item.name)}</div>'
            f'<div class="model-meta">{_e(item.provider)}/'
            f"{_e(item.model_name)}</div>"
            f"{stat_line}{consolidation_line}</div>"
        )
    return (
        '<h2 class="section">Models &amp; pipeline</h2>'
        f'<div class="models">{"".join(cards)}</div>'
    )


def render_compact_findings(
    title: str, findings: List[VulnerabilityFindingResponse]
) -> str:
    """A compact one-line-per-finding section, used for Remediated and
    Risk Accepted findings (#102)."""
    if not findings:
        return ""
    rows = []
    for f in findings:
        sev = f.severity or "Informational"
        note = ""
        if getattr(f, "disposition_note", None):
            note = f' <span class="cf-note">{_e(f.disposition_note)}</span>'
        rows.append(
            f'<li class="cf-row">'
            f'<span class="sev" style="background:{severity_color(sev)};'
            f'color:{severity_text_color(sev)}">{_e(sev)}</span>'
            f'<span class="cf-title">{_e(f.title)}</span> '
            f'<span class="cf-loc">{_e(f.file_path)}:{f.line_number}</span>'
            f"{note}</li>"
        )
    return (
        f'<h2 class="section">{_e(title)} ({len(findings)})</h2>'
        f'<ul class="compact">{"".join(rows)}</ul>'
    )


def provenance_label(finding: VulnerabilityFindingResponse) -> str:
    """Detector provenance for a finding — the SAST scanner that emitted
    it, or the reasoning LLM(s) that flagged it (#101)."""
    detectors = list(getattr(finding, "detected_by_llms", None) or [])
    source = getattr(finding, "source", None)
    if source and source != "agent":
        detectors = [source, *detectors]
    return ", ".join(detectors)
