"""Presentation helpers for immutable patch-plan artifacts.

The browser and report generators consume the persisted artifact directly.  This
module is the sole place that turns it into an apply-ready text export, avoiding
any reconstruction from finding snippets.
"""

from __future__ import annotations

from typing import Any

from app.shared.lib.patch_planner import PatchPlanArtifact


def _commented_physical_lines(value: object) -> list[str]:
    """Return metadata as inert patch comments, one prefix per physical line.

    ``str.splitlines`` recognizes CR, CRLF, LF, and Unicode line separators.
    Prefixing after that split prevents an untrusted metadata value from
    smuggling a fresh ``diff --git``/``---`` header into the apply stream.
    """

    physical_lines = str(value).splitlines() or [""]
    return [f"# {line}" if line else "#" for line in physical_lines]


def render_patch_export(payload: dict[str, Any]) -> str:
    """Render validated diffs as apply-ready and quarantine review-only diffs."""
    artifact = PatchPlanArtifact.model_validate(payload)
    lines: list[str] = []
    for metadata in (
        "SCCAP validated patch artifact",
        f"Scan: {artifact.scan_id}",
        f"Schema: {artifact.schema_version}",
    ):
        lines.extend(_commented_physical_lines(metadata))
    lines.append("#")
    for file_plan in artifact.files:
        lines.extend(_commented_physical_lines(f"File: {file_plan.file_path}"))
        lines.extend(
            _commented_physical_lines(f"Candidate state: {file_plan.status}")
        )
        for requirement in file_plan.requirements:
            lines.extend(
                _commented_physical_lines(f"Candidate: {requirement.candidate_id}")
            )
            for label, values in (
                ("Required import", requirement.required_imports),
                ("Required dependency", requirement.required_dependencies),
                ("Configuration change", requirement.configuration_changes),
                ("Migration change", requirement.migration_changes),
                ("Required command", requirement.required_commands),
                ("Manual step", requirement.manual_steps),
            ):
                for value in values:
                    lines.extend(_commented_physical_lines(f"{label}: {value}"))
        lines.append("#")
    apply_ready = [
        file_plan
        for file_plan in artifact.files
        if file_plan.status == "planned" and file_plan.unified_diff
    ]
    review_only = [
        file_plan
        for file_plan in artifact.files
        if file_plan.status != "planned" and file_plan.unified_diff
    ]
    lines.extend(
        _commented_physical_lines("--- BEGIN APPLY-READY UNIFIED DIFF ---")
    )
    lines.append("#")
    if not apply_ready:
        lines.append("# No validated apply-ready hunks are present.")
    for file_plan in apply_ready:
        if file_plan.unified_diff:
            lines.append(file_plan.unified_diff.rstrip("\n"))
    lines.append("#")
    lines.extend(_commented_physical_lines("--- END APPLY-READY UNIFIED DIFF ---"))
    lines.append("#")
    if review_only:
        lines.extend(
            _commented_physical_lines(
                "--- BEGIN REVIEW-ONLY CONTENT (NOT APPLY-READY) ---"
            )
        )
        lines.extend(
            _commented_physical_lines(
                "The following rejected/manual diffs are comments and are not applied by git apply."
            )
        )
        for file_plan in review_only:
            lines.extend(
                _commented_physical_lines(
                    f"File: {file_plan.file_path} · state: {file_plan.status}"
                )
            )
            lines.extend(_commented_physical_lines(file_plan.unified_diff))
        lines.extend(_commented_physical_lines("--- END REVIEW-ONLY CONTENT ---"))
        lines.append("#")
    return "\n".join(lines)
