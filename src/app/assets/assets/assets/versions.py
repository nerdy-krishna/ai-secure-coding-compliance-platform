"""Version comparison for CVE matching.

CVE ranges are written in whatever the affected product uses: `1.2.3`, `1.2`,
`2.0.0-beta1`, `1:1.2.3-4ubuntu5` (Debian epochs). A matcher that only understands
`X.Y.Z` silently reports "not affected", which is the worst kind of false negative
in this feature — so the comparison is deliberately forgiving: split into numeric
and non-numeric runs, compare numerically where both sides are numbers, and fall
back to a lexicographic comparison that still orders prereleases below releases.
"""

from __future__ import annotations

import re
from typing import Optional

_DELIMITER = re.compile(r"[._\-+~:]")
_NUMERIC = re.compile(r"^\d+$")


def normalise(version: str) -> str:
    return (version or "").strip().lstrip("vV=")


def _parts(version: str) -> list[str]:
    return [part for part in _DELIMITER.split(normalise(version)) if part != ""]


def _rank(token: str) -> tuple[int, int, str]:
    """Order tokens: numbers numerically, words below numbers, prereleases lower.

    A release always outranks its own prerelease (`1.2.0` > `1.2.0-rc1`), which is
    why words sort below numbers instead of by alphabet.
    """
    if _NUMERIC.match(token):
        return (1, int(token), "")
    lower = token.lower()
    # alpha/beta/rc/dev sorts below a missing token, "patch"/"p" above.
    return (0, 0, lower)


# A packaging revision, not part of the upstream version CVE ranges describe:
# "1.2.3-4ubuntu5", "1.2.3-1", "1.2.3-2.el9".
_PACKAGING_REVISION = re.compile(r"^(\d|.*(ubuntu|deb|el\d|fc\d|rhel|suse))", re.IGNORECASE)


def upstream(version: str) -> str:
    """Strip a Debian/RPM epoch and packaging revision.

    CVE ranges name upstream versions. A distro build (`1:1.2.3-4ubuntu5`) is
    compared as `1.2.3`, while a prerelease (`2.0.0-rc1`) keeps its suffix because
    that suffix is part of the upstream version.
    """
    cleaned = normalise(version)
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[1]
    if "-" in cleaned:
        head, tail = cleaned.rsplit("-", 1)
        if _PACKAGING_REVISION.match(tail):
            cleaned = head
    return cleaned


def compare(left: str, right: str) -> int:
    """-1, 0 or 1. Missing segments count as 0, so `1.2` == `1.2.0`."""
    left_parts, right_parts = _parts(left), _parts(right)
    for index in range(max(len(left_parts), len(right_parts))):
        left_token = left_parts[index] if index < len(left_parts) else "0"
        right_token = right_parts[index] if index < len(right_parts) else "0"
        left_rank, right_rank = _rank(left_token), _rank(right_token)
        if left_rank != right_rank:
            return -1 if left_rank < right_rank else 1
    return 0


def in_range(
    version: Optional[str],
    *,
    start_incl: Optional[str] = None,
    start_excl: Optional[str] = None,
    end_incl: Optional[str] = None,
    end_excl: Optional[str] = None,
    exact: Optional[list[str]] = None,
) -> bool:
    """Whether `version` falls inside a CVE range.

    Unbounded sides, an unknown version and absent bounds all behave predictably:
    an unknown version is *not* in range, because a range cannot be checked against
    nothing and claiming it can would invent certainty.
    """
    if not version:
        return False
    observed = upstream(version)
    if exact:
        return any(compare(observed, upstream(candidate)) == 0 for candidate in exact)
    if start_incl and compare(observed, upstream(start_incl)) < 0:
        return False
    if start_excl and compare(observed, upstream(start_excl)) <= 0:
        return False
    if end_incl and compare(observed, upstream(end_incl)) > 0:
        return False
    if end_excl and compare(observed, upstream(end_excl)) >= 0:
        return False
    return True


def product_matches(candidate: Optional[str], observed: Optional[str]) -> bool:
    """Loose product/package name matching.

    `nginx`, `NGINX`, `nginx/1.18.0` and `nginx:1.18.0` are the same product; so are
    `openssl` and `open_ssl`. Over-matching here is acceptable because every match
    still has to pass a version range and, for anything uncertain, a test.
    """
    if not candidate or not observed:
        return False

    def canon(value: str) -> str:
        squashed = re.sub(r"[^a-z0-9]", "", value.lower())
        # Banners often carry the version: "nginx/1.18.0" → "nginx".
        return re.sub(r"\d+(\.\d+)*.*$", "", squashed) or squashed

    left, right = canon(candidate), canon(observed)
    if not left or not right:
        return False
    return left == right or left in right or right in left
