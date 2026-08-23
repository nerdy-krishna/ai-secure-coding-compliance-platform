"""Stable identities and deterministic governance for finding fix candidates.

Identity deliberately excludes presentation fields such as title, CWE, severity,
and reported line.  Raw identities come from the durable producer invocation and
its occurrence index; site information belongs in the patch anchor fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from typing import Iterable, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.schemas import FixResult, VulnerabilityFinding


_LINEAGE_NAMESPACE = uuid.UUID("946feebc-138c-5d35-b0d5-45ca8b32de3d")


def _uuid(kind: str, *parts: object) -> uuid.UUID:
    value = json.dumps(
        [kind, *(str(part) for part in parts)],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return uuid.uuid5(_LINEAGE_NAMESPACE, value)


def raw_finding_id(
    scan_id: uuid.UUID | str, producer_key: str, occurrence_index: int
) -> uuid.UUID:
    """Return the replay-stable identity of one producer output occurrence."""
    if occurrence_index < 0:
        raise ValueError("occurrence_index must be non-negative")
    return _uuid("raw-finding-v1", scan_id, producer_key, occurrence_index)


def canonical_finding_id(raw_ids: Iterable[uuid.UUID | str]) -> uuid.UUID:
    """Return one order-independent identity for a consolidated finding."""
    members = sorted({str(value) for value in raw_ids})
    if not members:
        raise ValueError("canonical finding identity requires at least one raw id")
    return _uuid("canonical-finding-v1", *members)


def normalize_code(value: str) -> str:
    """Normalize line endings/trailing whitespace without changing indentation."""
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(line.rstrip() for line in lines)


def _fingerprint(kind: str, *parts: object) -> str:
    payload = json.dumps(
        [kind, *(str(part) for part in parts)],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def anchor_fingerprint(
    *,
    file_path: str,
    source_snapshot_hash: str,
    line_number: int,
    original_snippet: str,
) -> str:
    """Fingerprint an exact source site; repeated sites remain distinct."""
    return _fingerprint(
        "fix-anchor-v1",
        file_path,
        source_snapshot_hash,
        line_number,
        normalize_code(original_snippet),
    )


def patch_fingerprint(*, anchor: str, replacement_code: str) -> str:
    return _fingerprint("fix-patch-v1", anchor, normalize_code(replacement_code))


def fix_candidate_id(*, raw_id: uuid.UUID | str, patch: str) -> uuid.UUID:
    return _uuid("fix-candidate-v1", raw_id, patch)


def govern_fix_candidates(
    candidates: Sequence["FixResult"],
    flow_map: Sequence[dict],
    canonical_findings: Sequence["VulnerabilityFinding"],
) -> list["FixResult"]:
    """Apply consolidation decisions and choose at most one patch per root.

    Exact same-site/same-patch candidates are de-duplicated. Competing patches
    for the same anchor are held for manual review; no candidate is selected.
    Distinct sites are kept separate, even when their replacement text matches.
    """
    raw_decisions = {
        str(row.get("raw_finding_id")): row
        for row in flow_map
        if row.get("raw_finding_id")
    }
    canonical_by_id = {
        str(f.canonical_finding_id): f
        for f in canonical_findings
        if f.canonical_finding_id
    }

    governed = [candidate.model_copy(deep=True) for candidate in candidates]
    survivors: dict[str, list["FixResult"]] = defaultdict(list)
    for candidate in governed:
        raw_id = candidate.raw_finding_id or candidate.finding.raw_finding_id
        decision = raw_decisions.get(str(raw_id))
        if decision and decision.get("status") == "dropped":
            candidate.disposition = "rejected"
            candidate.decision_reason = (
                decision.get("false_positive_reason")
                or "Source finding was dropped during consolidation."
            )
            continue
        canonical_id = (
            decision.get("canonical_finding_id") if decision else None
        ) or candidate.finding.canonical_finding_id
        if not canonical_id:
            candidate.disposition = "rejected"
            candidate.decision_reason = "No surviving canonical finding."
            continue
        candidate.canonical_finding_id = uuid.UUID(str(canonical_id))
        survivors[str(canonical_id)].append(candidate)

    for canonical_id, group in survivors.items():
        # Remove exact duplicate producer proposals first.
        by_patch: dict[str, list["FixResult"]] = defaultdict(list)
        for candidate in group:
            by_patch[candidate.patch_fingerprint or ""].append(candidate)
        unique: list["FixResult"] = []
        for patch in sorted(by_patch):
            duplicates = sorted(
                by_patch[patch], key=lambda item: str(item.candidate_id or "")
            )
            unique.append(duplicates[0])
            for duplicate in duplicates[1:]:
                duplicate.disposition = "duplicate"
                duplicate.decision_reason = (
                    f"Exact duplicate of candidate {duplicates[0].candidate_id}."
                )

        anchors: dict[str, list["FixResult"]] = defaultdict(list)
        for candidate in unique:
            anchors[candidate.anchor_fingerprint or ""].append(candidate)
        has_conflict = any(len(values) > 1 for values in anchors.values())
        finding = canonical_by_id.get(canonical_id)
        if has_conflict:
            for values in anchors.values():
                for candidate in values:
                    candidate.disposition = "conflict"
                    candidate.decision_reason = "Competing patches target the same source anchor; manual review required."
            if finding:
                finding.fix_selection_status = "manual_review_required"
                finding.fixes = None
            continue

        # A canonical root can include several sites. Select each distinct site
        # for patch planning, while the display fix remains the deterministic
        # first site. This preserves repeated vulnerable occurrences.
        ordered = sorted(unique, key=lambda item: str(item.candidate_id or ""))
        for candidate in ordered:
            candidate.disposition = "selected"
            candidate.decision_reason = "Deterministic surviving candidate."
        if finding and ordered:
            finding.fix_selection_status = "selected"
            finding.fixes = ordered[0].suggestion

    return governed
