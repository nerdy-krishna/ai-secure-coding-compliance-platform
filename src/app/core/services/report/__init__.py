"""Findings-report generation.

One dedicated, format-native generator per output format — each takes a
scan's `AnalysisResultDetailResponse` and renders a high-quality report.
`generate_report` dispatches by format and is what the report endpoint
calls. PDF is added by a later slice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict

from app.api.v1.models import AnalysisResultDetailResponse
from app.core.services.report.csv_report import render_csv
from app.core.services.report.html_report import render_html


@dataclass(frozen=True)
class ReportArtifact:
    """A rendered report ready to stream to the client."""

    content: bytes
    media_type: str
    filename: str


# format -> (renderer, media type, file extension). Renderers return str;
# `generate_report` encodes to bytes.
_FORMATS: Dict[str, tuple] = {
    "html": (render_html, "text/html; charset=utf-8", "html"),
    "csv": (render_csv, "text/csv; charset=utf-8", "csv"),
}

SUPPORTED_FORMATS = tuple(_FORMATS)


def generate_report(result: AnalysisResultDetailResponse, fmt: str) -> ReportArtifact:
    """Render `result` into the requested format. Raises `ValueError`
    for an unsupported format so the caller can return a 400."""
    spec = _FORMATS.get(fmt)
    if spec is None:
        raise ValueError(
            f"Unsupported report format {fmt!r}; "
            f"expected one of {', '.join(SUPPORTED_FORMATS)}"
        )
    renderer: Callable[[AnalysisResultDetailResponse], str] = spec[0]
    media_type, ext = spec[1], spec[2]
    body = renderer(result)
    scan_id = result.summary_report.submission_id if result.summary_report else "scan"
    return ReportArtifact(
        content=body.encode("utf-8"),
        media_type=media_type,
        filename=f"scan-{scan_id}-report.{ext}",
    )
