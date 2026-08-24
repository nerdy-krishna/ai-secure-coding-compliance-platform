"""Deterministic, snapshot-bound patch range resolution and planning."""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import uuid
from datetime import datetime
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Callable, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field

from app.shared.lib.file_classification import LOW_VALUE_CATEGORIES, classify_file
from app.shared.lib.finding_lineage_identity import normalize_code

if TYPE_CHECKING:
    from app.core.schemas import FixResult


class ResolvedPatchRange(BaseModel):
    start_byte: int = Field(ge=0)
    end_byte: int = Field(ge=0)
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)


class CandidatePatchDecision(BaseModel):
    candidate_id: uuid.UUID
    status: Literal[
        "planned",
        "duplicate",
        "conflict",
        "ambiguous",
        "missing",
        "snapshot_mismatch",
        "noop",
        "invalid_path",
        "syntax_failed",
        "validation_failed",
        "validation_unavailable",
        "excluded",
    ]
    reason: str
    resolved_range: ResolvedPatchRange | None = None
    context_fingerprint: str | None = None
    patch_hunk_id: uuid.UUID | None = None


class PlannedPatchHunk(BaseModel):
    patch_hunk_id: uuid.UUID
    candidate_ids: list[uuid.UUID]
    resolved_range: ResolvedPatchRange
    context_fingerprint: str
    original_text: str
    replacement_text: str


class CandidateRequirements(BaseModel):
    candidate_id: uuid.UUID
    required_imports: list[str] = Field(default_factory=list)
    required_dependencies: list[str] = Field(default_factory=list)
    configuration_changes: list[str] = Field(default_factory=list)
    migration_changes: list[str] = Field(default_factory=list)
    required_commands: list[str] = Field(default_factory=list)
    manual_steps: list[str] = Field(default_factory=list)


class PatchValidationCheck(BaseModel):
    stage: str
    status: Literal[
        "passed",
        "failed",
        "not_run",
        "tool_missing",
        "timeout",
        "infrastructure_error",
        "skipped",
    ]
    blocking: bool = True
    tool: str | None = None
    profile: str | None = None
    tool_version: str | None = None
    completed_at: datetime | None = None
    detail: str
    return_code: int | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    output: str | None = Field(default=None, max_length=65_536)


class FilePatchPlan(BaseModel):
    file_path: str
    source_snapshot_hash: str
    output_hash: str
    status: Literal["planned", "manual_review_required", "no_changes"]
    hunks: list[PlannedPatchHunk] = Field(default_factory=list)
    conflict_components: list[list[uuid.UUID]] = Field(default_factory=list)
    requirements: list[CandidateRequirements] = Field(default_factory=list)
    validation_checks: list[PatchValidationCheck] = Field(default_factory=list)
    unified_diff: str = ""


class PatchPlanArtifact(BaseModel):
    schema_version: Literal[2] = 2
    scan_id: uuid.UUID
    files: list[FilePatchPlan] = Field(default_factory=list)
    candidate_decisions: list[CandidatePatchDecision] = Field(default_factory=list)


class _Resolved:
    def __init__(
        self,
        candidate: FixResult,
        start_char: int,
        end_char: int,
        resolved_range: ResolvedPatchRange,
        context_fingerprint: str,
        matched_original: str,
        replacement_text: str,
    ) -> None:
        self.candidate = candidate
        self.start_char = start_char
        self.end_char = end_char
        self.resolved_range = resolved_range
        self.context_fingerprint = context_fingerprint
        self.matched_original = matched_original
        self.replacement_text = replacement_text


_HUNK_NAMESPACE = uuid.UUID("527b9297-9da8-5b8d-b7c6-ebf5772a674d")


class PatchPlanLimits(BaseModel):
    """Fail-closed bounds for one file and the complete scan patch plan."""

    model_config = ConfigDict(frozen=True)

    max_hunks_per_file: int = Field(default=64, ge=1)
    max_hunks_per_plan: int = Field(default=256, ge=1)
    max_replacement_expansion_bytes_per_file: int = Field(default=256 * 1024, ge=1)
    max_replacement_expansion_bytes_per_plan: int = Field(default=1024 * 1024, ge=1)
    max_unified_diff_bytes_per_file: int = Field(default=512 * 1024, ge=1)
    max_unified_diff_bytes_per_plan: int = Field(default=2 * 1024 * 1024, ge=1)


DEFAULT_PATCH_PLAN_LIMITS = PatchPlanLimits()


class PatchPlanBudget:
    """Deterministic scan-scoped accounting shared by sorted file plans."""

    def __init__(self, limits: PatchPlanLimits = DEFAULT_PATCH_PLAN_LIMITS) -> None:
        self.limits = limits
        self.hunks = 0
        self.replacement_expansion_bytes = 0
        self.unified_diff_bytes = 0

    def plan_violation(
        self, *, hunks: int, replacement_expansion_bytes: int, unified_diff_bytes: int
    ) -> str | None:
        totals = (
            ("hunks", self.hunks + hunks, self.limits.max_hunks_per_plan),
            (
                "replacement expansion bytes",
                self.replacement_expansion_bytes + replacement_expansion_bytes,
                self.limits.max_replacement_expansion_bytes_per_plan,
            ),
            (
                "serialized unified-diff bytes",
                self.unified_diff_bytes + unified_diff_bytes,
                self.limits.max_unified_diff_bytes_per_plan,
            ),
        )
        for label, proposed, maximum in totals:
            if proposed > maximum:
                return (
                    f"Complete patch plan would contain {proposed} {label}; "
                    f"the automatic-planning limit is {maximum}."
                )
        return None

    def commit(
        self, *, hunks: int, replacement_expansion_bytes: int, unified_diff_bytes: int
    ) -> None:
        violation = self.plan_violation(
            hunks=hunks,
            replacement_expansion_bytes=replacement_expansion_bytes,
            unified_diff_bytes=unified_diff_bytes,
        )
        if violation is not None:
            raise ValueError(violation)
        self.hunks += hunks
        self.replacement_expansion_bytes += replacement_expansion_bytes
        self.unified_diff_bytes += unified_diff_bytes


def source_hash(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def normalize_relative_path(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or not normalized or ".." in candidate.parts:
        return None
    value = str(candidate)
    return None if value in {"", "."} else value


def _line_column(source: str, char_offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, char_offset) + 1
    prior_newline = source.rfind("\n", 0, char_offset)
    column = char_offset + 1 if prior_newline < 0 else char_offset - prior_newline
    return line, column


def _range(source: str, start: int, end: int) -> ResolvedPatchRange:
    start_line, start_column = _line_column(source, start)
    end_line, end_column = _line_column(source, end)
    return ResolvedPatchRange(
        start_byte=len(source[:start].encode("utf-8")),
        end_byte=len(source[:end].encode("utf-8")),
        start_line=start_line,
        start_column=start_column,
        end_line=end_line,
        end_column=end_column,
    )


def _context_fingerprint(source: str, start: int, end: int) -> str:
    before = source[max(0, start - 256) : start]
    after = source[end : min(len(source), end + 256)]
    payload = json.dumps(
        [before, source[start:end], after], ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _occurrences(source: str, needle: str) -> list[int]:
    starts: list[int] = []
    offset = 0
    while needle and (found := source.find(needle, offset)) >= 0:
        starts.append(found)
        offset = found + 1
    return starts


def _original_variants(original: str, source: str) -> list[str]:
    variants = [original]
    if "\r\n" in source and "\r\n" not in original:
        variants.append(original.replace("\n", "\r\n"))
    stripped = original.strip("\r\n")
    if stripped and stripped not in variants:
        variants.append(stripped)
        if "\r\n" in source and "\r\n" not in stripped:
            variants.append(stripped.replace("\n", "\r\n"))
    return list(dict.fromkeys(variants))


def _replacement_for_source(replacement: str, source: str) -> str:
    if "\r\n" in source:
        return replacement.replace("\r\n", "\n").replace("\n", "\r\n")
    return replacement.replace("\r\n", "\n").replace("\r", "\n")


def _import_insertion_offset(source: str, language: str | None) -> int | None:
    """Return a deterministic import insertion boundary for supported languages."""
    lines = source.splitlines(keepends=True)
    normalized = (language or "").lower()
    if normalized == "python":
        try:
            module = ast.parse(source)
        except SyntaxError:
            return None
        boundary_line = 0
        body = list(module.body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(getattr(body[0], "value", None), ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            boundary_line = body.pop(0).end_lineno or body[0].lineno
        for node in body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                boundary_line = node.end_lineno or node.lineno
            else:
                break
        if boundary_line == 0:
            for index, line in enumerate(lines[:2]):
                stripped = line.strip()
                if index == 0 and stripped.startswith("#!"):
                    boundary_line = 1
                elif "coding" in stripped and stripped.startswith("#"):
                    boundary_line = index + 1
        return sum(len(line) for line in lines[:boundary_line])
    if normalized in {"javascript", "typescript"}:
        boundary_line = 0
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "/*", "*")):
                if boundary_line == index:
                    boundary_line = index + 1
                continue
            if stripped.startswith("import "):
                boundary_line = index + 1
                continue
            break
        return sum(len(line) for line in lines[:boundary_line])
    if normalized == "java":
        boundary_line = 0
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(("package ", "import ")):
                boundary_line = index + 1
                continue
            break
        return sum(len(line) for line in lines[:boundary_line])
    return None


def _resolve_candidate(
    candidate: FixResult,
    *,
    file_path: str,
    source: str,
    expected_source_hash: str,
) -> tuple[_Resolved | None, CandidatePatchDecision]:
    candidate_id = candidate.candidate_id
    if candidate_id is None:
        raise ValueError("patch planner requires stable candidate_id")
    if normalize_relative_path(candidate.finding.file_path) != file_path:
        return None, CandidatePatchDecision(
            candidate_id=candidate_id,
            status="invalid_path",
            reason="Candidate path is not the normalized target path.",
        )
    if (
        candidate.source_snapshot_hash != expected_source_hash
        or source_hash(source) != expected_source_hash
    ):
        return None, CandidatePatchDecision(
            candidate_id=candidate_id,
            status="snapshot_mismatch",
            reason="Candidate or source content does not match the recorded snapshot hash.",
        )
    original = candidate.suggestion.original_snippet
    replacement = _replacement_for_source(candidate.suggestion.code, source)
    if not original:
        return None, CandidatePatchDecision(
            candidate_id=candidate_id,
            status="missing",
            reason="Candidate has no original anchor text.",
        )
    if normalize_code(original) == normalize_code(replacement):
        return None, CandidatePatchDecision(
            candidate_id=candidate_id,
            status="noop",
            reason="Replacement is identical to the original text.",
        )

    matches: list[tuple[int, str]] = []
    for variant in _original_variants(original, source):
        variant_matches = [(start, variant) for start in _occurrences(source, variant)]
        if variant_matches:
            matches = variant_matches
            break
    if not matches:
        return None, CandidatePatchDecision(
            candidate_id=candidate_id,
            status="missing",
            reason="Anchor text does not occur in the recorded source snapshot.",
        )

    expected_line = candidate.finding.line_number
    line_matches = [
        match for match in matches if _line_column(source, match[0])[0] == expected_line
    ]
    if len(line_matches) == 1:
        start, matched_original = line_matches[0]
    elif len(matches) == 1:
        start, matched_original = matches[0]
    else:
        return None, CandidatePatchDecision(
            candidate_id=candidate_id,
            status="ambiguous",
            reason=(
                "Anchor occurs more than once and the recorded line does not uniquely identify a site."
            ),
        )
    end = start + len(matched_original)
    resolved_range = _range(source, start, end)
    context = _context_fingerprint(source, start, end)
    return (
        _Resolved(
            candidate,
            start,
            end,
            resolved_range,
            context,
            matched_original,
            replacement,
        ),
        CandidatePatchDecision(
            candidate_id=candidate_id,
            status="planned",
            reason="Anchor resolved uniquely against the recorded source snapshot.",
            resolved_range=resolved_range,
            context_fingerprint=context,
        ),
    )


def validate_candidate_replacement(
    *,
    candidate: FixResult,
    file_path: str,
    source: str,
    expected_source_hash: str,
    syntax_validator: Callable[[str, str], bool | PatchValidationCheck] | None = None,
) -> CandidatePatchDecision:
    """Validate one replacement through the same exact anchor contract.

    This is the pre-planning gate used by global consolidation. It deliberately
    shares range resolution with the authoritative planner and never performs
    an occurrence-one string replacement.
    """
    if candidate.candidate_id is None:
        raise ValueError("patch validation requires stable candidate_id")
    normalized_path = normalize_relative_path(file_path)
    if normalized_path is None:
        return CandidatePatchDecision(
            candidate_id=candidate.candidate_id,
            status="invalid_path",
            reason="Candidate path is not a valid normalized relative path.",
        )
    item, decision = _resolve_candidate(
        candidate,
        file_path=normalized_path,
        source=source,
        expected_source_hash=expected_source_hash,
    )
    if item is None:
        return decision
    patched = (
        source[: item.start_char] + item.replacement_text + source[item.end_char :]
    )
    if syntax_validator:
        try:
            syntax_result = syntax_validator(patched, normalized_path)
            syntax_passed = (
                syntax_result.status == "passed"
                if isinstance(syntax_result, PatchValidationCheck)
                else bool(syntax_result)
            )
            if not syntax_passed:
                unavailable = (
                    isinstance(syntax_result, PatchValidationCheck)
                    and syntax_result.status != "failed"
                )
                decision.status = (
                    "validation_unavailable" if unavailable else "syntax_failed"
                )
                decision.reason = (
                    syntax_result.detail
                    if isinstance(syntax_result, PatchValidationCheck)
                    else "Candidate replacement fails whole-file syntax validation."
                )
        except Exception as exc:  # noqa: BLE001 - never convert errors to pass
            decision.status = "validation_unavailable"
            decision.reason = f"Syntax validator raised {type(exc).__name__}."
    return decision


def _overlaps(left: _Resolved, right: _Resolved) -> bool:
    return left.start_char < right.end_char and right.start_char < left.end_char


def _conflict_components(items: Sequence[_Resolved]) -> list[list[int]]:
    parents = list(range(len(items)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left in range(len(items)):
        for right in range(left + 1, len(items)):
            if _overlaps(items[left], items[right]):
                union(left, right)
    groups: dict[int, list[int]] = {}
    for index in range(len(items)):
        groups.setdefault(find(index), []).append(index)
    return [indices for indices in groups.values() if len(indices) > 1]


def _hunk_id(item: _Resolved) -> uuid.UUID:
    payload = ":".join(
        (
            str(item.candidate.candidate_id),
            str(item.resolved_range.start_byte),
            str(item.resolved_range.end_byte),
            hashlib.sha256(item.replacement_text.encode("utf-8")).hexdigest(),
        )
    )
    return uuid.uuid5(_HUNK_NAMESPACE, payload)


def _replacement_expansion_bytes(hunks: Sequence[PlannedPatchHunk]) -> int:
    return sum(
        max(
            0,
            len(hunk.replacement_text.encode("utf-8"))
            - len(hunk.original_text.encode("utf-8")),
        )
        for hunk in hunks
    )


def _file_limit_violation(
    *,
    hunks: int,
    replacement_expansion_bytes: int,
    unified_diff_bytes: int | None,
    limits: PatchPlanLimits,
) -> str | None:
    values: list[tuple[str, int, int]] = [
        ("hunks", hunks, limits.max_hunks_per_file),
        (
            "replacement expansion bytes",
            replacement_expansion_bytes,
            limits.max_replacement_expansion_bytes_per_file,
        ),
    ]
    if unified_diff_bytes is not None:
        values.append(
            (
                "serialized unified-diff bytes",
                unified_diff_bytes,
                limits.max_unified_diff_bytes_per_file,
            )
        )
    for label, actual, maximum in values:
        if actual > maximum:
            return (
                f"File patch would contain {actual} {label}; "
                f"the automatic-planning limit is {maximum}."
            )
    return None


def _mark_size_policy_conflicts(
    *,
    applicable: Sequence[_Resolved],
    decisions: Sequence[CandidatePatchDecision],
    conflict_ids: list[list[uuid.UUID]],
    reason: str,
) -> None:
    for item in applicable:
        candidate_id = item.candidate.candidate_id
        item.candidate.disposition = "conflict"
        item.candidate.applicability_status = "conflict"
        item.candidate.decision_reason = reason
        item.candidate.patch_hunk_id = None
        decision = next(
            value for value in decisions if value.candidate_id == candidate_id
        )
        decision.status = "conflict"
        decision.reason = reason
        decision.patch_hunk_id = None
        conflict_ids.append([candidate_id])


def plan_file_patch(
    *,
    file_path: str,
    source: str,
    expected_source_hash: str,
    candidates: Sequence[FixResult],
    syntax_validator: Callable[[str, str], bool] | None = None,
    dependency_validator: Callable[[FixResult], PatchValidationCheck] | None = None,
    import_validator: Callable[[FixResult], PatchValidationCheck] | None = None,
    allow_low_value: bool = False,
    limits: PatchPlanLimits = DEFAULT_PATCH_PLAN_LIMITS,
    plan_budget: PatchPlanBudget | None = None,
) -> tuple[FilePatchPlan, list[CandidatePatchDecision], str]:
    """Resolve, de-duplicate, conflict-check, and atomically apply one file plan."""
    normalized_path = normalize_relative_path(file_path)
    if normalized_path is None:
        raise ValueError(f"invalid target file path: {file_path!r}")

    requirements = [
        CandidateRequirements(
            candidate_id=candidate.candidate_id,
            required_imports=candidate.required_imports,
            required_dependencies=candidate.required_dependencies,
            configuration_changes=candidate.configuration_changes,
            migration_changes=candidate.migration_changes,
            required_commands=candidate.required_commands,
            manual_steps=candidate.manual_steps,
        )
        for candidate in candidates
    ]
    classification = classify_file(normalized_path, source).get("classification")
    if classification in LOW_VALUE_CATEGORIES and not allow_low_value:
        decisions: list[CandidatePatchDecision] = []
        for candidate in candidates:
            candidate.disposition = "rejected"
            candidate.applicability_status = "excluded"
            candidate.decision_reason = f"Patch planning excludes low-value/generated category {classification}."
            decisions.append(
                CandidatePatchDecision(
                    candidate_id=candidate.candidate_id,
                    status="excluded",
                    reason=candidate.decision_reason,
                )
            )
        return (
            FilePatchPlan(
                file_path=normalized_path,
                source_snapshot_hash=expected_source_hash,
                output_hash=source_hash(source),
                status="no_changes",
                requirements=requirements,
            ),
            decisions,
            source,
        )

    decisions = []
    requirement_checks: list[PatchValidationCheck] = []
    preliminary_conflicts: list[list[uuid.UUID]] = []
    resolved: list[_Resolved] = []
    for candidate in candidates:
        import_check: PatchValidationCheck | None = None
        if import_validator is not None:
            try:
                import_check = import_validator(candidate)
            except Exception as exc:  # noqa: BLE001 - becomes explicit evidence
                import_check = PatchValidationCheck(
                    stage="import_requirements",
                    status="infrastructure_error",
                    tool="static-import-resolver",
                    detail=(
                        f"Candidate {candidate.candidate_id} import validation "
                        f"raised {type(exc).__name__}."
                    ),
                )
            requirement_checks.append(import_check)
        elif candidate.required_imports:
            import_check = PatchValidationCheck(
                stage="import_requirements",
                status="not_run",
                tool="static-import-resolver",
                detail=(
                    f"Candidate {candidate.candidate_id} imports were not resolved "
                    "against the repository snapshot and dependency manifests."
                ),
            )
            requirement_checks.append(import_check)
        imports_ready = (
            import_check.status == "passed"
            if import_check is not None
            else not candidate.required_imports
        )
        dependency_check: PatchValidationCheck | None = None
        if candidate.required_dependencies:
            if dependency_validator is None:
                dependency_check = PatchValidationCheck(
                    stage="dependency_requirements",
                    status="not_run",
                    tool="manifest-inventory",
                    detail=(
                        f"Candidate {candidate.candidate_id} dependency requirements "
                        "were not checked against repository manifests."
                    ),
                )
            else:
                try:
                    dependency_check = dependency_validator(candidate)
                except Exception as exc:  # noqa: BLE001 - becomes explicit evidence
                    dependency_check = PatchValidationCheck(
                        stage="dependency_requirements",
                        status="infrastructure_error",
                        tool="manifest-inventory",
                        detail=(
                            f"Candidate {candidate.candidate_id} dependency validation "
                            f"raised {type(exc).__name__}."
                        ),
                    )
            requirement_checks.append(dependency_check)
        dependencies_ready = not candidate.required_dependencies or (
            dependency_check is not None and dependency_check.status == "passed"
        )
        manual_requirements = (
            candidate.configuration_changes
            or candidate.migration_changes
            or candidate.required_commands
            or candidate.manual_steps
        )
        if manual_requirements:
            requirement_checks.append(
                PatchValidationCheck(
                    stage="manual_requirements",
                    status="failed",
                    tool=None,
                    detail=(
                        f"Candidate {candidate.candidate_id} requires configuration, "
                        "migration, commands, or operator steps outside this "
                        "source-file patch."
                    ),
                )
            )
        import_offset = _import_insertion_offset(source, candidate.language)
        import_unavailable = candidate.required_imports and import_offset is None
        if import_unavailable:
            requirement_checks.append(
                PatchValidationCheck(
                    stage="import_requirements",
                    status="failed",
                    tool="deterministic-import-planner",
                    detail=(
                        f"Candidate {candidate.candidate_id} imports cannot be placed "
                        "deterministically for this language."
                    ),
                )
            )
        if (
            not dependencies_ready
            or not imports_ready
            or manual_requirements
            or (candidate.required_imports and import_offset is None)
        ):
            candidate.disposition = "conflict"
            candidate.applicability_status = "conflict"
            candidate.validation_status = "failed"
            if not dependencies_ready and dependency_check is not None:
                candidate.decision_reason = dependency_check.detail
            elif not imports_ready and import_check is not None:
                candidate.decision_reason = import_check.detail
            elif manual_requirements:
                candidate.decision_reason = (
                    "Configuration, migration, command, or manual requirements need "
                    "a separately approved change."
                )
            else:
                candidate.decision_reason = "Required imports cannot be placed deterministically for this language."
            decisions.append(
                CandidatePatchDecision(
                    candidate_id=candidate.candidate_id,
                    status="conflict",
                    reason=candidate.decision_reason,
                )
            )
            preliminary_conflicts.append([candidate.candidate_id])
            continue
        item, decision = _resolve_candidate(
            candidate,
            file_path=normalized_path,
            source=source,
            expected_source_hash=expected_source_hash,
        )
        decisions.append(decision)
        if item is not None:
            resolved.append(item)
        else:
            candidate.disposition = "rejected"
            candidate.applicability_status = decision.status
            candidate.decision_reason = decision.reason

    # The planner repeats duplicate defense at the authoritative resolved-range
    # seam even though candidate governance normally removed them earlier.
    by_edit: dict[tuple[int, int, str], list[_Resolved]] = {}
    for item in resolved:
        key = (item.start_char, item.end_char, item.replacement_text)
        by_edit.setdefault(key, []).append(item)
    unique: list[_Resolved] = []
    duplicate_ids: set[uuid.UUID] = set()
    for values in by_edit.values():
        ordered = sorted(values, key=lambda item: str(item.candidate.candidate_id))
        unique.append(ordered[0])
        for duplicate in ordered[1:]:
            duplicate_ids.add(duplicate.candidate.candidate_id)
            duplicate.candidate.disposition = "duplicate"
            duplicate.candidate.applicability_status = "duplicate"
            duplicate.candidate.decision_reason = f"Resolved edit duplicates candidate {ordered[0].candidate.candidate_id}."
    for decision in decisions:
        if decision.candidate_id in duplicate_ids:
            decision.status = "duplicate"
            decision.reason = "Resolved edit is an exact duplicate."

    conflict_components = _conflict_components(unique)
    conflicted_indices = {index for group in conflict_components for index in group}
    conflict_ids: list[list[uuid.UUID]] = list(preliminary_conflicts)
    for component in conflict_components:
        ids = [unique[index].candidate.candidate_id for index in component]
        conflict_ids.append(ids)
        for index in component:
            item = unique[index]
            item.candidate.disposition = "conflict"
            item.candidate.applicability_status = "conflict"
            item.candidate.decision_reason = (
                "Resolved range overlaps another candidate; manual review required."
            )
            decision = next(
                d for d in decisions if d.candidate_id == item.candidate.candidate_id
            )
            decision.status = "conflict"
            decision.reason = item.candidate.decision_reason

    applicable = [
        item for index, item in enumerate(unique) if index not in conflicted_indices
    ]
    hunks: list[PlannedPatchHunk] = []
    edits: list[tuple[int, int, str]] = []
    for item in applicable:
        hunk_id = _hunk_id(item)
        item.candidate.resolved_range = item.resolved_range
        item.candidate.context_fingerprint = item.context_fingerprint
        item.candidate.patch_hunk_id = hunk_id
        item.candidate.applicability_status = "planned"
        decision = next(
            d for d in decisions if d.candidate_id == item.candidate.candidate_id
        )
        decision.patch_hunk_id = hunk_id
        hunks.append(
            PlannedPatchHunk(
                patch_hunk_id=hunk_id,
                candidate_ids=[item.candidate.candidate_id],
                resolved_range=item.resolved_range,
                context_fingerprint=item.context_fingerprint,
                original_text=item.matched_original,
                replacement_text=item.replacement_text,
            )
        )
        edits.append((item.start_char, item.end_char, item.replacement_text))

    missing_imports: dict[str, set[uuid.UUID]] = {}
    for item in applicable:
        existing_lines = {line.strip() for line in source.splitlines()}
        for required_import in item.candidate.required_imports:
            normalized_import = required_import.strip()
            if normalized_import and normalized_import not in existing_lines:
                missing_imports.setdefault(normalized_import, set()).add(
                    item.candidate.candidate_id
                )
    if missing_imports:
        import_offset = _import_insertion_offset(
            source, applicable[0].candidate.language
        )
        if import_offset is not None:
            newline = "\r\n" if "\r\n" in source else "\n"
            import_text = newline.join(sorted(missing_imports)) + newline
            if import_offset and source[import_offset - 1] not in "\r\n":
                import_text = newline + import_text
            linked_ids = sorted(
                {
                    candidate_id
                    for ids in missing_imports.values()
                    for candidate_id in ids
                },
                key=str,
            )
            context = _context_fingerprint(source, import_offset, import_offset)
            import_range = _range(source, import_offset, import_offset)
            import_hunk_id = uuid.uuid5(
                _HUNK_NAMESPACE,
                json.dumps(
                    [str(value) for value in linked_ids]
                    + [str(import_offset), import_text],
                    separators=(",", ":"),
                ),
            )
            hunks.append(
                PlannedPatchHunk(
                    patch_hunk_id=import_hunk_id,
                    candidate_ids=linked_ids,
                    resolved_range=import_range,
                    context_fingerprint=context,
                    original_text="",
                    replacement_text=import_text,
                )
            )
            edits.append((import_offset, import_offset, import_text))

    replacement_expansion_bytes = _replacement_expansion_bytes(hunks)
    limit_violation = _file_limit_violation(
        hunks=len(hunks),
        replacement_expansion_bytes=replacement_expansion_bytes,
        unified_diff_bytes=None,
        limits=limits,
    )
    proposed_diff = ""
    proposed_diff_bytes = 0
    if limit_violation is None:
        proposed = source
        for start, end, replacement in sorted(
            edits, key=lambda value: value[0], reverse=True
        ):
            proposed = proposed[:start] + replacement + proposed[end:]
        proposed_diff = "".join(
            difflib.unified_diff(
                source.splitlines(keepends=True),
                proposed.splitlines(keepends=True),
                fromfile=f"a/{normalized_path}",
                tofile=f"b/{normalized_path}",
            )
        )
        proposed_diff_bytes = len(proposed_diff.encode("utf-8"))
        limit_violation = _file_limit_violation(
            hunks=len(hunks),
            replacement_expansion_bytes=replacement_expansion_bytes,
            unified_diff_bytes=proposed_diff_bytes,
            limits=limits,
        )
    if limit_violation is None and plan_budget is not None:
        limit_violation = plan_budget.plan_violation(
            hunks=len(hunks),
            replacement_expansion_bytes=replacement_expansion_bytes,
            unified_diff_bytes=proposed_diff_bytes,
        )
    if limit_violation is not None and hunks:
        _mark_size_policy_conflicts(
            applicable=applicable,
            decisions=decisions,
            conflict_ids=conflict_ids,
            reason=f"{limit_violation} Manual review is required.",
        )
        requirement_checks.append(
            PatchValidationCheck(
                stage="patch_size_policy",
                status="failed",
                tool="deterministic-patch-planner",
                detail=f"{limit_violation} Automatic patch output was discarded.",
            )
        )
        hunks = []
        edits = []

    patched = source
    for start, end, replacement in sorted(
        edits, key=lambda value: value[0], reverse=True
    ):
        patched = patched[:start] + replacement + patched[end:]

    validation_checks: list[PatchValidationCheck] = list(requirement_checks)
    if hunks and syntax_validator:
        try:
            syntax_result = syntax_validator(patched, normalized_path)
            if isinstance(syntax_result, PatchValidationCheck):
                syntax_check = syntax_result
            else:
                syntax_check = PatchValidationCheck(
                    stage="syntax",
                    status="passed" if syntax_result else "failed",
                    tool="configured_parser",
                    detail=(
                        "Patched file passed syntax validation."
                        if syntax_result
                        else "Patched file failed syntax validation."
                    ),
                )
        except Exception as exc:  # noqa: BLE001 - exceptions are evidence
            syntax_check = PatchValidationCheck(
                stage="syntax",
                status="infrastructure_error",
                tool="configured_parser",
                detail=f"Syntax validator raised {type(exc).__name__}.",
            )
        validation_checks.append(syntax_check)
    elif hunks:
        syntax_check = PatchValidationCheck(
            stage="syntax",
            status="not_run",
            blocking=False,
            tool=None,
            detail="No syntax validator was configured for this planning run.",
        )
        validation_checks.append(syntax_check)
    else:
        syntax_check = None

    if syntax_check and syntax_check.blocking and syntax_check.status != "passed":
        patched = source
        unavailable = syntax_check.status != "failed"
        if unavailable:
            conflict_ids.extend([item.candidate.candidate_id] for item in applicable)
        for item in applicable:
            item.candidate.disposition = "conflict" if unavailable else "rejected"
            item.candidate.validation_status = "not_run" if unavailable else "failed"
            item.candidate.applicability_status = (
                "validation_unavailable" if unavailable else "syntax_failed"
            )
            item.candidate.decision_reason = syntax_check.detail
            item.candidate.patch_hunk_id = None
        for decision in decisions:
            if decision.patch_hunk_id:
                decision.status = (
                    "validation_unavailable" if unavailable else "syntax_failed"
                )
                decision.reason = syntax_check.detail
                decision.patch_hunk_id = None
        hunks = []

    if limit_violation is None and proposed_diff and hunks:
        validation_checks.append(
            PatchValidationCheck(
                stage="patch_size_policy",
                status="passed",
                tool="deterministic-patch-planner",
                detail=(
                    f"Accepted {len(hunks)} hunks, {replacement_expansion_bytes} "
                    "replacement expansion bytes, and "
                    f"{proposed_diff_bytes} serialized unified-diff bytes."
                ),
            )
        )
        if plan_budget is not None:
            plan_budget.commit(
                hunks=len(hunks),
                replacement_expansion_bytes=replacement_expansion_bytes,
                unified_diff_bytes=proposed_diff_bytes,
            )

    unified_diff = "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{normalized_path}",
            tofile=f"b/{normalized_path}",
        )
    )
    status: Literal["planned", "manual_review_required", "no_changes"]
    if conflict_ids:
        status = "manual_review_required"
    elif hunks:
        status = "planned"
    else:
        status = "no_changes"
    return (
        FilePatchPlan(
            file_path=normalized_path,
            source_snapshot_hash=expected_source_hash,
            output_hash=source_hash(patched),
            status=status,
            hunks=sorted(hunks, key=lambda value: value.resolved_range.start_byte),
            conflict_components=conflict_ids,
            requirements=requirements,
            validation_checks=validation_checks,
            unified_diff=unified_diff,
        ),
        decisions,
        patched,
    )
