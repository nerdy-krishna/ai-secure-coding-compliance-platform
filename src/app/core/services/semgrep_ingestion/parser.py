# src/app/core/services/semgrep_ingestion/parser.py
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _stringify_keys(value: Any) -> Any:
    """Recursively cast mapping keys to strings.

    YAML 1.1 resolves bare ``on``/``off``/``yes``/``no``/``true``/``false`` keys
    and numeric scalars to non-string mapping keys. ``json.dumps(...,
    sort_keys=True)`` compares keys directly, so one such key anywhere in a rule
    raises ``TypeError: '<' not supported between instances of 'bool' and
    'str'`` and aborted the whole source sync (elttam ``jsp-likely-xss``,
    Minded Security ``MSTG-ARCH-9``).

    Only rules that previously failed to hash are affected: for rules whose keys
    are already strings this returns an equal structure, so existing digests - and
    therefore replay verification of rules ingested before this fix - are stable.
    """
    if isinstance(value, dict):
        return {str(key): _stringify_keys(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_stringify_keys(item) for item in value]
    return value


def semgrep_rule_content_hash(raw_rule: dict[str, Any]) -> str:
    """Return the canonical digest used to bind an ingested Semgrep rule.

    Replay recomputes this value from ``raw_yaml`` instead of trusting the
    mutable database digest column alone.
    """
    canonical = json.dumps(_stringify_keys(raw_rule), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _extract_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val] if val else []
    if isinstance(val, list):
        return [str(v) for v in val if v]
    return []


def _extract_cwe(val: Any) -> list[str]:
    raw = _extract_list(val)
    result = []
    for item in raw:
        matches = _CWE_RE.findall(item)
        for m in matches:
            result.append(f"CWE-{m}")
        if not matches and item:
            result.append(item)
    return result


def _normalize_rule(
    raw_rule: dict, source: db_models.SemgrepRuleSource, relative_path: str
) -> dict | None:
    rule_id = raw_rule.get("id")
    if not rule_id or not isinstance(rule_id, str):
        return None

    namespaced_id = f"{source.slug}.{rule_id}"

    meta = raw_rule.get("metadata") or {}
    languages = _extract_list(raw_rule.get("languages"))
    technology = _extract_list(meta.get("technology") or meta.get("technologies"))
    cwe = _extract_cwe(meta.get("cwe") or meta.get("cwe-id"))
    owasp = _extract_list(meta.get("owasp") or meta.get("owasp-top-10"))

    severity = str(raw_rule.get("severity", "WARNING")).upper()
    if severity not in ("ERROR", "WARNING", "INFO"):
        severity = "WARNING"

    message = str(raw_rule.get("message", ""))[:2000]

    # Canonical JSON for content hash — stable across runs.
    # YAML allows non-string keys (bool / number); cast to str so
    # sorted() doesn't fail with mixed-type comparison errors.
    content_hash = semgrep_rule_content_hash(raw_rule)

    return {
        "namespaced_id": namespaced_id,
        "original_id": rule_id,
        "relative_path": relative_path,
        "languages": languages,
        "severity": severity,
        "category": str(meta.get("category", "")) or None,
        "technology": technology,
        "cwe": cwe,
        "owasp": owasp,
        "confidence": str(meta.get("confidence", "")) or None,
        "likelihood": str(meta.get("likelihood", "")) or None,
        "impact": str(meta.get("impact", "")) or None,
        "message": message,
        "raw_yaml": raw_rule,
        "content_hash": content_hash,
        "license_spdx": source.license_spdx,
        "enabled": True,
    }


def parse_rule_file(
    path: Path, source: db_models.SemgrepRuleSource, repo_root: Path
) -> list[dict]:
    """Parse a Semgrep YAML rule file. Returns a list of normalized rule dicts."""
    relative_path = str(path.relative_to(repo_root))
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError as exc:
        logger.debug(
            "semgrep.parser.yaml_error",
            extra={"path": relative_path, "error": str(exc)},
        )
        return []

    if not isinstance(raw, dict):
        return []
    rules_list = raw.get("rules")
    if not isinstance(rules_list, list):
        return []

    results = []
    for raw_rule in rules_list:
        if not isinstance(raw_rule, dict):
            continue
        # A single pathological rule must not fail the whole source: log it, count
        # it as invalid, and keep ingesting the rest of the repository.
        try:
            normalized = _normalize_rule(raw_rule, source, relative_path)
        except Exception as exc:  # noqa: BLE001 - isolate per-rule parse failures
            logger.warning(
                "semgrep.parser.rule_failed",
                extra={
                    "source": source.slug,
                    "path": relative_path,
                    "rule_id": str(raw_rule.get("id"))[:200],
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
            continue
        if normalized:
            results.append(normalized)
    return results
