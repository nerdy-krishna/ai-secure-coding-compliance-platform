"""How long a scan actually worked, as opposed to how long it has existed.

`created_at → completed_at` is wall clock: it counts the minutes (or hours) a scan
sits at an approval gate waiting for a human, and the time it spends queued behind
other work. Neither is scan duration, and a 3-minute scan that waited 20 minutes for
review should not be reported as 23 minutes.

The only place a SAST scan deliberately waits for a person is an approval gate
(`approval_gates`), so the correction is exact rather than heuristic:

    active = (end - created_at) - Σ(gate decided/now - gate created)

A gate that has not been decided yet counts up to *now*, so a scan parked at the
prescan card reads as frozen instead of ticking.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional, Sequence, Tuple


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def waiting_seconds(
    gates: Iterable[Tuple[Optional[datetime], Optional[datetime]]],
    *,
    until: datetime,
) -> float:
    """Total seconds spent parked at approval gates."""
    total = 0.0
    for opened_at, decided_at in gates:
        start = _as_utc(opened_at)
        if start is None:
            continue
        end = _as_utc(decided_at) or until
        if end < start:
            continue
        total += (end - start).total_seconds()
    return total


def active_processing_seconds(
    *,
    created_at: Optional[datetime],
    completed_at: Optional[datetime] = None,
    gates: Sequence[Tuple[Optional[datetime], Optional[datetime]]] = (),
    now: Optional[datetime] = None,
) -> Optional[float]:
    """Seconds the scan was actually working, excluding gate waits.

    Returns ``None`` when there is nothing to measure (no creation timestamp).
    """
    start = _as_utc(created_at)
    if start is None:
        return None
    current = _as_utc(now) or datetime.now(timezone.utc)
    end = _as_utc(completed_at) or current
    if end < start:
        return 0.0
    span = (end - start).total_seconds()
    waited = waiting_seconds(gates, until=end)
    return max(0.0, span - waited)


def gate_intervals(gates: Iterable[object]) -> list[Tuple[Optional[datetime], Optional[datetime]]]:
    """Adapt ApprovalGate ORM rows to ``(created_at, decided_at)`` pairs."""
    return [
        (getattr(gate, "created_at", None), getattr(gate, "decided_at", None))
        for gate in gates
    ]
