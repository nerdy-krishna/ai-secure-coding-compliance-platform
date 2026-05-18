"""Finding disposition (triage) state machine.

A pure, dependency-free module — the single source of truth for the
operator-controlled disposition vocabulary, the allowed transitions, and
which transitions require a written justification note. The API
validation layer imports it; it opens no DB session and is unit-testable
in isolation.

PRD #96 / slice #97. Five states; `open` is the default for every newly
created finding. `false_positive`, `remediated`, and `risk_accepted`
drop a finding out of all risk math (consumed by slice #99 — the
vocabulary lives here so it stays in one place).
"""

from __future__ import annotations

from typing import FrozenSet, Optional

OPEN = "open"
CONFIRMED = "confirmed"
FALSE_POSITIVE = "false_positive"
REMEDIATED = "remediated"
RISK_ACCEPTED = "risk_accepted"

#: Every valid disposition.
DISPOSITIONS: FrozenSet[str] = frozenset(
    {OPEN, CONFIRMED, FALSE_POSITIVE, REMEDIATED, RISK_ACCEPTED}
)

#: The disposition a finding is created with.
DEFAULT_DISPOSITION: str = OPEN

#: States whose findings still count toward the risk score (`confirmed`
#: is scored identically to `open`; it is purely a workflow signal).
SCOREABLE: FrozenSet[str] = frozenset({OPEN, CONFIRMED})

#: States whose findings are excluded from all risk math.
NON_SCOREABLE: FrozenSet[str] = DISPOSITIONS - SCOREABLE

#: Transitions *to* these states demand a non-empty justification note —
#: the risk-significant ones, where the decision must be defensible.
_NOTE_REQUIRED_TARGETS: FrozenSet[str] = frozenset({FALSE_POSITIVE, RISK_ACCEPTED})


class DispositionError(ValueError):
    """An invalid disposition value, a no-op transition, or a missing
    required justification note."""


def is_valid_disposition(value: str) -> bool:
    """True when `value` is one of the five known states."""
    return value in DISPOSITIONS


def is_scoreable(disposition: str) -> bool:
    """True when a finding in this disposition counts toward the risk
    score. Unknown values are treated as scoreable (fail-open — a bad
    disposition must never silently hide a finding from the score)."""
    return disposition not in NON_SCOREABLE


def note_required(target: str) -> bool:
    """True when moving a finding *to* `target` requires a note."""
    return target in _NOTE_REQUIRED_TARGETS


def can_transition(current: str, target: str) -> bool:
    """True when `current` may move to `target`.

    Any disposition may move to any other — re-triage is always allowed
    (e.g. `remediated` back to `open` if a fix regressed). Only a no-op
    (`current == target`) and unknown targets are rejected, so a
    redundant write never lands in the audit log.
    """
    return is_valid_disposition(target) and current != target


def validate_transition(current: str, target: str, note: Optional[str]) -> None:
    """Raise `DispositionError` if the transition is invalid or a
    required justification note is missing/blank; return None on success.
    """
    if not is_valid_disposition(target):
        raise DispositionError(f"Unknown disposition {target!r}.")
    if current == target:
        raise DispositionError(f"Finding is already {target!r}; nothing to change.")
    if note_required(target) and not (note and note.strip()):
        raise DispositionError(
            f"A justification note is required to mark a finding " f"{target!r}."
        )
