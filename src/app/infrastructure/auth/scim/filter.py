"""Minimal SCIM 2.0 filter parser.

Supported operators (RFC 7644 §3.4.2.2 subset):
  - userName eq "value"
  - emails.value eq "value"
  - emails[type eq "work"].value eq "value"  → NOT supported (returns 400)
  - active eq true / false

Anything else raises ``UnsupportedScimFilter``. Callers map that to
HTTP 400 with the SCIM Error schema.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


class UnsupportedScimFilter(ValueError):
    """The filter uses syntax / operators we don't implement yet."""


@dataclass(slots=True, frozen=True)
class ScimFilterClause:
    """Resolved filter clause: ``attribute eq value``."""

    attribute: str  # "userName" | "active" | "emails.value"
    value: str | bool


# Strict whitelist of recognised attribute paths. New attributes need
# explicit grammar handling AND a binding to the SQLAlchemy column.
_ALLOWED_ATTRS = {"userName", "active", "emails.value"}


# eq filter: <attr> eq <value>
# Value is either:
#   - a quoted string ("foo bar")
#   - a bare boolean (true / false)
#   - a bare number (not currently used by allowlist)
_FILTER_RE = re.compile(
    r"""
    ^\s*
    (?P<attr>[a-zA-Z][\w.]*)        # attribute path
    \s+(?P<op>eq)\s+                # operator (only `eq` for now)
    (?:
        \"(?P<sval>[^\"\\]*)\"     # quoted string
      | (?P<bval>true|false)        # boolean literal
    )
    \s*$
    """,
    re.VERBOSE | re.IGNORECASE,
)


def parse_filter(raw: Optional[str]) -> Optional[ScimFilterClause]:
    """Parse a SCIM filter; return None when no filter was provided.

    Raises ``UnsupportedScimFilter`` for anything we can't represent.
    """
    if raw is None or not raw.strip():
        return None
    m = _FILTER_RE.match(raw)
    if not m:
        raise UnsupportedScimFilter(
            "filter syntax not supported; only single-clause `eq` "
            "comparisons on userName, active, or emails.value are recognised"
        )
    attr = m.group("attr")
    if attr not in _ALLOWED_ATTRS:
        raise UnsupportedScimFilter(
            f"filter attribute {attr!r} not supported "
            f"(allowed: {sorted(_ALLOWED_ATTRS)})"
        )
    if m.group("sval") is not None:
        value: str | bool = m.group("sval")
    else:
        value = m.group("bval").lower() == "true"
    return ScimFilterClause(attribute=attr, value=value)
