"""CVSS-compatible severity labels for SCCAP's 0-10 risk score."""

from __future__ import annotations


def risk_severity_for_score(score: float) -> str:
    """Return the CVSS severity band for a numeric score.

    Callers persist integer scores today, but accepting floats keeps the
    boundary definition correct if score precision is widened later.
    """
    bounded = max(0.0, min(10.0, float(score)))
    if bounded == 0.0:
        return "None"
    if bounded < 4.0:
        return "Low"
    if bounded < 7.0:
        return "Medium"
    if bounded < 9.0:
        return "High"
    return "Critical"
