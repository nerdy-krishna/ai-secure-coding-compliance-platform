"""Pure policies shared by approval-producing and approval-consuming paths."""

from __future__ import annotations

from typing import Any, Mapping


HIGH_VALUE_COST_USD = 50.0


def requires_dual_cost_approval(cost_details: Mapping[str, Any]) -> bool:
    """Return whether the conservative persisted estimate crosses the threshold."""
    raw = cost_details.get("upper_bound_estimated_cost")
    if raw is None:
        # Compatibility for estimates persisted before range support.
        raw = cost_details.get("total_estimated_cost")
    if raw is None or isinstance(raw, bool):
        return False
    try:
        return float(raw) >= HIGH_VALUE_COST_USD
    except (TypeError, ValueError):
        return False


def is_strict_approval(payload: Mapping[str, Any]) -> bool:
    """Only a literal JSON boolean true advances an approval gate."""
    return payload.get("approved") is True
