"""Deterministic file classification for scan coverage policy.

The classifier is deliberately fail-open: callers that catch an exception should
fall back to ``unknown`` / normal analysis. It uses cheap path/name/content
signals only; no LLM or external I/O.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, Optional

CATEGORY_FIRST_PARTY_SOURCE = "first_party_source"
CATEGORY_FIRST_PARTY_MINIFIED_BUNDLE = "first_party_minified_bundle"
CATEGORY_KNOWN_THIRD_PARTY_VENDOR = "known_third_party_vendor"
CATEGORY_UNKNOWN_THIRD_PARTY_VENDOR = "unknown_third_party_vendor"
CATEGORY_GENERATED_ASSET = "generated_asset"
CATEGORY_LARGE_STATIC_ASSET = "large_static_asset"
CATEGORY_UNKNOWN = "unknown"

LOW_VALUE_CATEGORIES = {
    CATEGORY_FIRST_PARTY_MINIFIED_BUNDLE,
    CATEGORY_KNOWN_THIRD_PARTY_VENDOR,
    CATEGORY_UNKNOWN_THIRD_PARTY_VENDOR,
    CATEGORY_GENERATED_ASSET,
    CATEGORY_LARGE_STATIC_ASSET,
}

_TEXT_STATIC_EXTENSIONS = {
    ".css",
    ".map",
    ".svg",
    ".json",
    ".lock",
    ".min.css",
}

_SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".rs",
}

_VENDOR_LIB_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "jquery",
        re.compile(
            r"jquery(?:-|\.min)?\.js|jQuery JavaScript Library|jquery v?\d", re.I
        ),
    ),
    (
        "bootstrap",
        re.compile(
            r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)|Bootstrap v?\d", re.I
        ),
    ),
    ("lodash", re.compile(r"lodash(?:\.min)?\.js|lodash\.com|Lo-Dash", re.I)),
    ("react", re.compile(r"react(?:\.production\.min)?\.js|React v?\d", re.I)),
    ("vue", re.compile(r"vue(?:\.runtime)?(?:\.min)?\.js|Vue\.js v?\d", re.I)),
    ("angular", re.compile(r"angular(?:\.min)?\.js|AngularJS v?\d", re.I)),
    ("moment", re.compile(r"moment(?:\.min)?\.js|Moment\.js", re.I)),
    ("popper", re.compile(r"popper(?:\.min)?\.js|@popperjs", re.I)),
)

_VENDOR_PATH_RE = re.compile(
    r"(^|/)(vendor|vendors|third[-_]?party|node_modules|bower_components)(/|$)", re.I
)
_GENERATED_PATH_RE = re.compile(
    r"(^|/)(dist|build|coverage|generated|gen|out|target)(/|$)", re.I
)
_SOURCE_MAP_RE = re.compile(
    r"//# sourceMappingURL=(?P<url>\S+)|/\*# sourceMappingURL=(?P<css_url>[^*]+)\*/"
)
_VERSION_RE = re.compile(r"(?:v|version\s*)?(\d+\.\d+(?:\.\d+)?)", re.I)


def is_minified_content(path: str, content: str) -> bool:
    lower = path.lower()
    if ".min." in lower or lower.endswith(".min.js") or lower.endswith(".min.css"):
        return True
    lines = [line for line in content.splitlines() if line.strip()]
    if not lines:
        return False
    avg_len = sum(len(line) for line in lines[:200]) / min(len(lines), 200)
    semicolons = content.count(";")
    newlines = max(1, content.count("\n"))
    return avg_len > 300 or semicolons / newlines > 40


def _detect_source_map(content: str) -> Optional[str]:
    match = _SOURCE_MAP_RE.search(content[-4096:])
    if not match:
        return None
    return (match.group("url") or match.group("css_url") or "").strip()


def _known_library(path: str, content: str) -> tuple[Optional[str], Optional[str]]:
    sample = f"{path}\n{content[:4096]}"
    for name, pattern in _VENDOR_LIB_PATTERNS:
        if pattern.search(sample):
            version_match = _VERSION_RE.search(sample)
            return name, version_match.group(1) if version_match else None
    return None, None


def _has_matching_source_map(
    path: str, source_map_url: Optional[str], submitted_paths: set[str]
) -> bool:
    if not source_map_url or source_map_url.startswith(
        ("http://", "https://", "data:")
    ):
        return False
    source_map_path = str(PurePosixPath(path).parent / source_map_url)
    return source_map_url in submitted_paths or source_map_path in submitted_paths


def classify_file(
    path: str,
    content: str,
    *,
    submitted_paths: Optional[Iterable[str]] = None,
    dependency_evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return structured classification/coverage policy metadata for one file."""
    submitted_set = set(submitted_paths or [])
    lower_path = path.lower()
    suffix = PurePosixPath(lower_path).suffix
    size_bytes = len(content.encode("utf-8", "replace"))
    source_map_url = _detect_source_map(content)
    has_source_map = _has_matching_source_map(path, source_map_url, submitted_set)
    minified = is_minified_content(path, content)
    library, version = _known_library(path, content)
    evidence: list[str] = []

    if library:
        category = CATEGORY_KNOWN_THIRD_PARTY_VENDOR
        evidence.append(f"known_library:{library}")
    elif _VENDOR_PATH_RE.search(lower_path):
        category = CATEGORY_UNKNOWN_THIRD_PARTY_VENDOR
        evidence.append("vendor_path")
    elif minified and suffix in {".js", ".css"}:
        category = CATEGORY_FIRST_PARTY_MINIFIED_BUNDLE
        evidence.append("minified_bundle")
    elif _GENERATED_PATH_RE.search(lower_path) or has_source_map:
        category = CATEGORY_GENERATED_ASSET
        evidence.append("generated_path_or_source_map")
    elif size_bytes > 1_000_000 and suffix in _TEXT_STATIC_EXTENSIONS:
        category = CATEGORY_LARGE_STATIC_ASSET
        evidence.append("large_static_asset")
    elif suffix in _SOURCE_EXTENSIONS:
        category = CATEGORY_FIRST_PARTY_SOURCE
        evidence.append("source_extension")
    else:
        category = CATEGORY_UNKNOWN
        evidence.append("no_strong_signal")

    if dependency_evidence:
        evidence.append("dependency_evidence")

    policy = {
        "llm_profile": category not in LOW_VALUE_CATEGORIES,
        "llm_analysis": category not in LOW_VALUE_CATEGORIES,
        "semgrep": category not in LOW_VALUE_CATEGORIES,
        "gitleaks": size_bytes <= 1_000_000,
        "dependency_intel": category == CATEGORY_KNOWN_THIRD_PARTY_VENDOR,
    }
    warnings: list[str] = []
    if category == CATEGORY_FIRST_PARTY_MINIFIED_BUNDLE and not has_source_map:
        warnings.append("missing_source_map_reduced_client_coverage")
    if category in LOW_VALUE_CATEGORIES:
        warnings.append("reduced_low_value_asset_coverage")

    return {
        "classification": category,
        "size_bytes": size_bytes,
        "content_sha256": hashlib.sha256(
            content.encode("utf-8", "replace")
        ).hexdigest(),
        "is_minified": minified,
        "known_library": {"name": library, "version": version} if library else None,
        "source_map": {"url": source_map_url, "submitted": has_source_map},
        "coverage_policy": policy,
        "coverage_warnings": warnings,
        "evidence": evidence,
    }


def should_skip_llm_profile(
    profile: Dict[str, Any], *, deep_vendor_scan: bool = False
) -> bool:
    if deep_vendor_scan:
        return False
    return not bool((profile.get("coverage_policy") or {}).get("llm_profile", True))


def should_skip_llm_analysis(
    profile: Dict[str, Any], *, deep_vendor_scan: bool = False
) -> bool:
    if deep_vendor_scan:
        return False
    return not bool((profile.get("coverage_policy") or {}).get("llm_analysis", True))


def should_skip_semgrep(
    profile: Dict[str, Any], *, deep_vendor_scan: bool = False
) -> bool:
    if deep_vendor_scan:
        return False
    return not bool((profile.get("coverage_policy") or {}).get("semgrep", True))
