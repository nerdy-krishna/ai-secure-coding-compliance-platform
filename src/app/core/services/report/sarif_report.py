"""SARIF 2.1.0 findings-report generator.

The output is intentionally conservative and GitHub Code Scanning friendly:

* one SARIF run with a stable SCCAP tool driver;
* deterministic rule IDs and rule indexes;
* repository-relative, URI-escaped artifact locations under %SRCROOT%;
* primary locations plus relatedLocations for merged/affected sites;
* CVSS/CWE/source/triage metadata preserved in properties.
"""

from __future__ import annotations

import json
import posixpath
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

from app.api.v1.models import AnalysisResultDetailResponse, VulnerabilityFindingResponse
from app.core.services.report._common import collect_findings

_TOOL_NAME = "SCCAP"
_INFORMATION_URI = "https://github.com/secure-coding-platform/sccap"
_SEMANTIC_VERSION = "1.0.0"
_URI_BASE_ID = "%SRCROOT%"

_SEVERITY_TO_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "note",
}

_PRECISION_BY_CONFIDENCE = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
}


def render_sarif(result: AnalysisResultDetailResponse) -> str:
    """Render a scan result as SARIF 2.1.0 JSON text."""
    findings = collect_findings(result)
    rules: List[Dict[str, Any]] = []
    rule_indexes: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        rule_id = _rule_id(finding)
        rule_index = rule_indexes.get(rule_id)
        if rule_index is None:
            rule_index = len(rules)
            rule_indexes[rule_id] = rule_index
            rules.append(_rule(rule_id, finding))
        results.append(_result(finding, rule_id, rule_index))

    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _INFORMATION_URI,
                        "semanticVersion": _SEMANTIC_VERSION,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {_URI_BASE_ID: {"uri": "file:///"}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _rule_id(finding: VulnerabilityFindingResponse) -> str:
    source = _slug(getattr(finding, "source", None) or "agent")
    cwe = _normalize_cwe(getattr(finding, "cwe", None))
    title = _slug(finding.title or "finding")
    parts = [source]
    if cwe:
        parts.append(cwe)
    parts.append(title)
    return "/".join(parts)


def _rule(rule_id: str, finding: VulnerabilityFindingResponse) -> Dict[str, Any]:
    short = finding.title or rule_id
    full = finding.description or finding.title or rule_id
    help_text = _help_markdown(finding)
    tags = ["security"]
    cwe = _normalize_cwe(getattr(finding, "cwe", None))
    if cwe:
        tags.append(f"external/cwe/{cwe.lower()}")

    properties: Dict[str, Any] = {
        "tags": tags,
        "precision": _precision(finding),
        "security-severity": _security_severity(finding),
    }
    if cwe:
        properties["cwe"] = cwe
    if finding.cvss_score is not None:
        properties["cvss_score"] = finding.cvss_score
    if finding.cvss_vector:
        properties["cvss_vector"] = finding.cvss_vector
    source = getattr(finding, "source", None)
    if source:
        properties["source"] = source

    rule: Dict[str, Any] = {
        "id": rule_id,
        "name": short[:120],
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "help": {"text": _plain_help(finding), "markdown": help_text},
        "properties": properties,
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _result(
    finding: VulnerabilityFindingResponse, rule_id: str, rule_index: int
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _level(finding),
        "message": {"text": finding.title or finding.description or rule_id},
        "locations": [
            _location(
                finding.file_path, finding.line_number, finding.vulnerable_snippet
            )
        ],
        "properties": _result_properties(finding),
    }

    related = _related_locations(finding)
    if related:
        out["relatedLocations"] = related
    return out


def _result_properties(finding: VulnerabilityFindingResponse) -> Dict[str, Any]:
    props: Dict[str, Any] = {
        "finding_id": finding.id,
        "severity": finding.severity,
        "source": getattr(finding, "source", None) or "agent",
        "confidence": finding.confidence,
        "disposition": getattr(finding, "disposition", None) or "open",
    }
    if finding.cvss_score is not None:
        props["cvss_score"] = finding.cvss_score
    if finding.cvss_vector:
        props["cvss_vector"] = finding.cvss_vector
    cwe = _normalize_cwe(getattr(finding, "cwe", None))
    if cwe:
        props["cwe"] = cwe
    if getattr(finding, "detected_by_llms", None):
        props["detected_by_llms"] = finding.detected_by_llms
    if getattr(finding, "corroborating_agents", None):
        props["corroborating_agents"] = finding.corroborating_agents
    if getattr(finding, "cross_file_status", None):
        props["cross_file_status"] = finding.cross_file_status
    if getattr(finding, "cross_file_rationale", None):
        props["cross_file_rationale"] = finding.cross_file_rationale
    if getattr(finding, "disposition_note", None):
        props["disposition_note"] = finding.disposition_note
    if finding.references:
        props["references"] = finding.references
    if finding.remediation:
        props["remediation"] = finding.remediation
    return props


def _location(
    path: str, line: int | None, snippet: str | None = None
) -> Dict[str, Any]:
    physical: Dict[str, Any] = {
        "artifactLocation": {"uri": _artifact_uri(path), "uriBaseId": _URI_BASE_ID}
    }
    if isinstance(line, int) and line > 0:
        region: Dict[str, Any] = {"startLine": line}
        if snippet:
            region["snippet"] = {"text": snippet}
        physical["region"] = region
    return {"physicalLocation": physical}


def _related_locations(finding: VulnerabilityFindingResponse) -> List[Dict[str, Any]]:
    related: List[Dict[str, Any]] = []
    seen: set[Tuple[str, int | None, str | None]] = set()
    primary = (finding.file_path, finding.line_number, finding.vulnerable_snippet)
    seen.add(primary)

    for index, loc in enumerate(finding.affected_locations or [], start=1):
        if not isinstance(loc, dict):
            continue
        line = loc.get("line_number")
        snippet = loc.get("snippet")
        path = loc.get("file_path") or finding.file_path
        if not isinstance(line, int):
            continue
        snippet_text = snippet if isinstance(snippet, str) else None
        key = (str(path), line, snippet_text)
        if key in seen:
            continue
        seen.add(key)
        related_loc = _location(str(path), line, snippet_text)
        related_loc["id"] = index
        related_loc["message"] = {"text": "Additional affected location"}
        related.append(related_loc)
    return related


def _artifact_uri(path: str) -> str:
    normalized = str(path or "unknown").replace("\\", "/")
    normalized = re.sub(r"^[A-Za-z]:/", "", normalized)
    normalized = normalized.lstrip("/")
    normalized = posixpath.normpath(normalized)
    if normalized == ".":
        normalized = "unknown"
    while normalized.startswith("../"):
        normalized = normalized[3:]
    return quote(normalized, safe="/@:+,;=%")


def _level(finding: VulnerabilityFindingResponse) -> str:
    return _SEVERITY_TO_LEVEL.get(finding.severity, "warning")


def _precision(finding: VulnerabilityFindingResponse) -> str:
    return _PRECISION_BY_CONFIDENCE.get(finding.confidence, "medium")


def _security_severity(finding: VulnerabilityFindingResponse) -> str:
    if finding.cvss_score is not None:
        return f"{finding.cvss_score:.1f}"
    fallback = {
        "Critical": "9.0",
        "High": "7.0",
        "Medium": "5.0",
        "Low": "3.0",
        "Informational": "0.0",
    }
    return fallback.get(finding.severity, "0.0")


def _normalize_cwe(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"(\d+)", value)
    if not match:
        return _slug(value).upper() or None
    return f"CWE-{match.group(1)}"


def _slug(value: str) -> str:
    text = value.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "finding"


def _plain_help(finding: VulnerabilityFindingResponse) -> str:
    parts = [finding.description or finding.title]
    if finding.remediation:
        parts.append(f"Remediation: {finding.remediation}")
    if finding.references:
        parts.append("References: " + ", ".join(finding.references))
    return "\n\n".join(part for part in parts if part)


def _help_markdown(finding: VulnerabilityFindingResponse) -> str:
    parts = [finding.description or finding.title]
    if finding.remediation:
        parts.append(f"**Remediation:** {finding.remediation}")
    if finding.cvss_score is not None:
        cvss = f"**CVSS:** {finding.cvss_score:.1f}"
        if finding.cvss_vector:
            cvss += f" `{finding.cvss_vector}`"
        parts.append(cvss)
    if finding.references:
        refs = "\n".join(f"- {ref}" for ref in finding.references)
        parts.append(f"**References:**\n{refs}")
    return "\n\n".join(part for part in parts if part)
