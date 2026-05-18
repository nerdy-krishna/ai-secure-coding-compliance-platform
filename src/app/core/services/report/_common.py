"""Shared helpers for the findings-report generators.

Includes the report palette (PRD #96 / #98): reports are standalone
documents and cannot reference the website's live CSS variables, so the
values of the light / variant-A design tokens (see
``secure-code-ui/src/app/styles/tokens.css``) are inlined here once and
shared by the HTML and PDF generators. Print-tuned — white surfaces, the
app's accent and severity colors, no dark theme.
"""

from __future__ import annotations

from typing import Dict, List

from app.api.v1.models import AnalysisResultDetailResponse, VulnerabilityFindingResponse

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
