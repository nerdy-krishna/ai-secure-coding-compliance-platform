"""Immutable evidence for deterministic scanner inputs.

Runtime probes are cached per worker process. A scan still receives its own
snapshot so later image or rule-source changes cannot rewrite what operators
were told ran at scan time.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from app.infrastructure.scanners.bandit_runner import _bandit_binary
from app.infrastructure.scanners.gitleaks_runner import (
    _gitleaks_binary,
    _gitleaks_config_path,
)
from app.infrastructure.scanners.osv_runner import _osv_binary
from app.infrastructure.scanners.semgrep_runner import _semgrep_binary
from app.core.services.semgrep_ingestion.parser import semgrep_rule_content_hash
from app.shared.lib.owned_subprocess import run_owned_subprocess

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"(?<![0-9])([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?![0-9])")


class SemgrepRuleBindingError(ValueError):
    """The persisted prescan evidence cannot safely bind a replay ruleset."""


# Expected runtime evidence for the architecture built by Dockerfile. The Go
# binaries/config are release-asset hashes; the Python entry-point hashes are
# stable because their venv locations are fixed in the image.
_SCANNER_SPECS: Mapping[str, Mapping[str, Any]] = {
    "bandit": {
        "binary": _bandit_binary,
        "version_args": ("--version",),
        "version": "1.9.4",
        "sha256": "dd6fb6f6220c136d08879209e843b39966a10940a2de4c99ba833dfe77157c9e",
        "configuration_identifier": "bandit-default-plugins@1.9.4",
    },
    "semgrep": {
        "binary": _semgrep_binary,
        "version_args": ("--version",),
        "version": "1.95.0",
        "sha256": "658f5b43f67014e3e1fc9c106f07516ea03082a03b4b0d3c536d768ef0de3eec",
        "configuration_identifier": "scan-selected-database-rules",
    },
    "gitleaks": {
        "binary": _gitleaks_binary,
        "version_args": ("version",),
        "version": "8.21.2",
        "sha256": "50b742abd7daad8bbddb6301f3017efb680632d9a5b3b4d8f137b3aac250e359",
        "config": _gitleaks_config_path,
        "config_sha256": "2ce9d818ed5aac0d9a36638a317284bd733c26d5069c980829335183397430bb",
    },
    "osv": {
        "binary": _osv_binary,
        "version_args": ("--version",),
        "version": "2.3.5",
        "sha256": "bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b",
        "configuration_identifier": "osv-scanner-default",
    },
}


def sha256_file(path: Path) -> Optional[str]:
    """Hash a regular file, returning ``None`` when it is unavailable."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def build_scanner_provenance(
    *,
    scanner: str,
    binary_path: Path,
    detected_version: Optional[str],
    expected_version: str,
    expected_binary_sha256: str,
    config_path: Optional[Path] = None,
    expected_config_sha256: Optional[str] = None,
    configuration_identifier: Optional[str] = None,
    advisory_database: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Build one scanner record and explicitly degrade every mismatch."""
    reasons: list[str] = []
    binary_sha256 = sha256_file(binary_path)
    if binary_sha256 is None:
        reasons.append("binary_unavailable")
    elif binary_sha256 != expected_binary_sha256:
        reasons.append("binary_digest_mismatch")
    if detected_version is None:
        reasons.append("version_unavailable")
    elif detected_version != expected_version:
        reasons.append("version_mismatch")

    configuration: dict[str, Any]
    if config_path is not None:
        config_sha256 = sha256_file(config_path)
        configuration = {
            "kind": "file",
            "path": str(config_path),
            "sha256": config_sha256,
            "expected_sha256": expected_config_sha256,
        }
        if config_sha256 is None:
            reasons.append("configuration_unavailable")
        elif expected_config_sha256 and config_sha256 != expected_config_sha256:
            reasons.append("configuration_digest_mismatch")
    else:
        configuration = {
            "kind": "built_in_or_runtime",
            "identifier": configuration_identifier or "not_applicable",
        }

    advisory = dict(advisory_database) if advisory_database else None
    if advisory and not advisory.get("immutable", False):
        reasons.append(str(advisory.get("reason") or "advisory_database_unpinned"))

    immutable = not reasons
    return {
        "scanner": scanner,
        "status": "verified" if immutable else "degraded",
        "immutable": immutable,
        "reasons": reasons,
        "binary": {
            "path": str(binary_path),
            "version": detected_version,
            "expected_version": expected_version,
            "sha256": binary_sha256,
            "expected_sha256": expected_binary_sha256,
        },
        "configuration": configuration,
        **({"advisory_database": advisory} if advisory else {}),
    }


def _detect_version(binary: Path, args: Sequence[str]) -> Optional[str]:
    try:
        completed = run_owned_subprocess(
            [str(binary), *args],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = _VERSION_RE.search(f"{completed.stdout}\n{completed.stderr}"[:4096])
    return match.group(1) if match else None


@functools.cache
def collect_runtime_provenance() -> dict[str, dict[str, Any]]:
    """Probe the four configured scanner runtimes once per worker process."""
    records: dict[str, dict[str, Any]] = {}
    for scanner, spec in _SCANNER_SPECS.items():
        binary = Path(spec["binary"]()).resolve()
        config = spec.get("config")
        if callable(config):
            config = config()
        advisory_database = spec.get("advisory_database")
        if scanner == "osv":
            # Local import avoids a module cycle: the strict offline adapter
            # reuses OSV's validated native-report parser.
            from app.infrastructure.scanners.osv_offline_replay import (
                advisory_provenance,
            )

            advisory_database = advisory_provenance()
        records[scanner] = build_scanner_provenance(
            scanner=scanner,
            binary_path=binary,
            detected_version=_detect_version(binary, spec["version_args"]),
            expected_version=spec["version"],
            expected_binary_sha256=os.getenv(
                f"SCCAP_{scanner.upper()}_BINARY_SHA256", spec["sha256"]
            ),
            config_path=Path(config) if config else None,
            expected_config_sha256=os.getenv(
                "SCCAP_GITLEAKS_CONFIG_SHA256", str(spec.get("config_sha256") or "")
            )
            or None,
            configuration_identifier=(
                f"signed-offline-release:{os.environ['SCCAP_OFFLINE_VERIFIED_RELEASE_SHA256']}"
                if scanner in {"semgrep", "gitleaks", "osv"}
                and os.getenv("SCCAP_OFFLINE_VERIFIED_RELEASE_SHA256")
                else spec.get("configuration_identifier")
            ),
            advisory_database=advisory_database,
        )
    return records


def build_semgrep_rule_provenance(
    rules: Iterable[Any], sources: Iterable[Any]
) -> dict[str, Any]:
    """Snapshot exact selected rule bodies and their resolved source commits."""
    source_by_id = {str(source.id): source for source in sources}
    source_records: list[dict[str, Any]] = []
    reasons: list[str] = []
    used_source_ids = sorted({str(rule.source_id) for rule in rules})
    for source_id in used_source_ids:
        source = source_by_id.get(source_id)
        if source is None:
            reasons.append(f"source_metadata_missing:{source_id}")
            continue
        commit = getattr(source, "last_commit_sha", None)
        slug = str(getattr(source, "slug", source_id))
        commit_valid = isinstance(commit, str) and bool(_GIT_SHA_RE.fullmatch(commit))
        if not commit_valid:
            reasons.append(f"source_commit_missing:{slug}")
        source_records.append(
            {
                "id": source_id,
                "slug": slug,
                "repo_url": str(getattr(source, "repo_url", "")),
                "configured_ref": str(getattr(source, "branch", "")),
                "resolved_commit_sha": commit if commit_valid else None,
                "immutable": commit_valid,
            }
        )

    rule_records: list[dict[str, Any]] = []
    for rule in sorted(rules, key=lambda item: str(item.namespaced_id)):
        content_hash = str(getattr(rule, "content_hash", ""))
        rule_id = str(rule.namespaced_id)
        if not _SHA256_RE.fullmatch(content_hash):
            reasons.append(f"rule_digest_missing:{rule_id}")
        raw_body = getattr(rule, "raw_yaml", None)
        if not isinstance(raw_body, dict):
            reasons.append(f"rule_body_missing:{rule_id}")
        elif semgrep_rule_content_hash(raw_body) != content_hash:
            reasons.append(f"rule_body_digest_mismatch:{rule_id}")
        rule_records.append(
            {
                "id": rule_id,
                "content_sha256": content_hash or None,
                "source_id": str(rule.source_id),
                "license_spdx": str(getattr(rule, "license_spdx", "")),
                "body": raw_body if isinstance(raw_body, dict) else None,
            }
        )

    canonical = json.dumps(rule_records, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    ruleset_digest = hashlib.sha256(canonical).hexdigest()
    immutable = not reasons
    return {
        "status": "verified" if immutable else "degraded",
        "immutable": immutable,
        "reasons": reasons,
        "selected_rule_count": len(rule_records),
        "ruleset_sha256": ruleset_digest,
        "sources": source_records,
        "rules": rule_records,
    }


def parse_semgrep_rule_binding(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return the exact Semgrep ruleset recorded by prescan.

    New evidence contains each historical rule body and binds it to the same
    canonical digest used at ingestion. Legacy hash-only artifacts fail closed
    for replay but remain downloadable during migration.
    """
    if payload.get("schema_version") != 1:
        raise SemgrepRuleBindingError("scanner_report_schema_missing")
    toolchain = payload.get("toolchain_provenance")
    if not isinstance(toolchain, Mapping):
        raise SemgrepRuleBindingError("toolchain_provenance_missing")
    semgrep = toolchain.get("semgrep")
    if not isinstance(semgrep, Mapping):
        raise SemgrepRuleBindingError("semgrep_provenance_missing")
    ruleset = semgrep.get("rules")
    if not isinstance(ruleset, Mapping):
        raise SemgrepRuleBindingError("semgrep_rule_provenance_missing")
    if ruleset.get("status") != "verified" or ruleset.get("immutable") is not True:
        raise SemgrepRuleBindingError("semgrep_rule_provenance_degraded")

    raw_rules = ruleset.get("rules")
    if not isinstance(raw_rules, list):
        raise SemgrepRuleBindingError("semgrep_rule_inventory_missing")
    selected_count = ruleset.get("selected_rule_count")
    if not isinstance(selected_count, int) or isinstance(selected_count, bool):
        raise SemgrepRuleBindingError("semgrep_rule_count_invalid")
    if selected_count != len(raw_rules) or selected_count > 5_000:
        raise SemgrepRuleBindingError("semgrep_rule_count_mismatch")

    source_records = ruleset.get("sources")
    if not isinstance(source_records, list):
        raise SemgrepRuleBindingError("semgrep_source_inventory_missing")
    source_ids: set[str] = set()
    for record in source_records:
        if not isinstance(record, Mapping):
            raise SemgrepRuleBindingError("semgrep_source_record_invalid")
        source_id = record.get("id")
        commit = record.get("resolved_commit_sha")
        if (
            not isinstance(source_id, str)
            or not source_id
            or source_id in source_ids
            or record.get("immutable") is not True
            or not isinstance(commit, str)
            or not _GIT_SHA_RE.fullmatch(commit)
        ):
            raise SemgrepRuleBindingError("semgrep_source_record_invalid")
        source_ids.add(source_id)

    normalized: list[dict[str, Any]] = []
    bindings: dict[str, dict[str, str]] = {}
    for record in raw_rules:
        if not isinstance(record, Mapping):
            raise SemgrepRuleBindingError("semgrep_rule_record_invalid")
        rule_id = record.get("id")
        digest = record.get("content_sha256")
        source_id = record.get("source_id")
        license_spdx = record.get("license_spdx")
        body = record.get("body")
        if (
            not isinstance(rule_id, str)
            or not rule_id
            or len(rule_id) > 512
            or rule_id in bindings
            or not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
            or not isinstance(source_id, str)
            or source_id not in source_ids
            or not isinstance(license_spdx, str)
            or not isinstance(body, dict)
            or semgrep_rule_content_hash(body) != digest
        ):
            raise SemgrepRuleBindingError("semgrep_rule_record_invalid")
        bindings[rule_id] = {
            "content_sha256": digest,
            "source_id": source_id,
            "license_spdx": license_spdx,
            "body": body,
        }
        normalized.append(
            {
                "id": rule_id,
                "content_sha256": digest,
                "source_id": source_id,
                "license_spdx": license_spdx,
                "body": body,
            }
        )

    normalized.sort(key=lambda item: item["id"])
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    ruleset_digest = hashlib.sha256(canonical).hexdigest()
    if ruleset.get("ruleset_sha256") != ruleset_digest:
        raise SemgrepRuleBindingError("semgrep_ruleset_digest_mismatch")

    scanner_statuses = payload.get("scanner_statuses")
    semgrep_status = (
        scanner_statuses.get("semgrep")
        if isinstance(scanner_statuses, Mapping)
        else None
    )
    if not isinstance(semgrep_status, Mapping):
        raise SemgrepRuleBindingError("semgrep_execution_provenance_missing")
    if semgrep_status.get("native_report_available") is not True:
        raise SemgrepRuleBindingError("semgrep_native_report_missing")
    if semgrep_status.get("status") not in {"completed", "degraded"}:
        raise SemgrepRuleBindingError("semgrep_prescan_not_completed")

    return {
        "rules": bindings,
        "selected_rule_count": selected_count,
        "ruleset_sha256": ruleset_digest,
    }


def summarize_toolchain_provenance(
    provenance: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Return the bounded operator/report view; omit the per-rule inventory."""
    summary: dict[str, Any] = {}
    for scanner, record in provenance.items():
        compact = dict(record)
        semgrep_rules = compact.get("rules")
        if scanner == "semgrep" and isinstance(semgrep_rules, Mapping):
            compact["rules"] = {
                key: value for key, value in semgrep_rules.items() if key != "rules"
            }
        summary[scanner] = compact
    return summary
