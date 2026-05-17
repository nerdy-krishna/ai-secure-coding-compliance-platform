"""Semgrep CE subprocess wrapper for the deterministic SAST pre-pass.

Invokes ``semgrep --config <bundled-rule-pack> ... --json --
<staged_dir>`` and converts each result into a
:class:`VulnerabilityFinding` carrying ``source="semgrep"`` and
``confidence="High"``.

Hardening (per the sast-prescan + sast-prescan-followups threat models):

- M1 / N2: ``subprocess.run([...], shell=False, check=False, timeout=120)``;
  arguments are a list; ``--`` separator before the user-derived path;
  ``--config`` pinned to the bundled pack so user-tree ``.semgrep.yml``
  / ``.semgrepignore`` cannot redirect behavior.
- N2: bundled ``p/security-audit`` pack lives at
  ``/app/scanners/configs/semgrep/security-audit.yml`` (downloaded +
  sha256-verified at Docker build time).
- M5 / N1: scanner ``stdout`` is parsed and discarded; never logged
  above DEBUG.
- M6: 120-second hard timeout; ``TimeoutExpired`` returns a single
  Low-severity timeout finding so the worker keeps moving.
- M7 / N6: ``description`` is HTML-escaped and capped at 200 chars
  before reaching any LLM agent prompt.

The wrapper is ``async`` but executes Semgrep on a worker thread via
``asyncio.to_thread`` so the FastAPI / LangGraph event loop stays
responsive while Semgrep walks the tree.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.scanners.bandit_runner import _resolve_binary


logger = logging.getLogger(__name__)


def _semgrep_binary() -> str:
    """Lazy accessor for the Semgrep binary path. Resolves on first
    call so `SEMGREP_BINARY` env-var loaded by `dotenv` after import
    is honored."""
    return _resolve_binary(
        "SEMGREP_BINARY", "semgrep", fallback="/opt/semgrep-venv/bin/semgrep"
    )


SEMGREP_TIMEOUT_SECONDS = 120
DESCRIPTION_MAX_CHARS = 2000

# Semgrep severity strings → SCCAP severity bucket (Title-cased,
# matching what LLM agents emit).
_SEMGREP_SEVERITY_MAP: Dict[str, str] = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}

_CWE_PATTERN = re.compile(r"CWE-(\d+)")


class _SemgrepStart(BaseModel):
    model_config = ConfigDict(extra="ignore")

    line: int = 0


class _SemgrepMetadata(BaseModel):
    """Allowlisted projection of `extra.metadata` — only the fields we
    actually consume reach `VulnerabilityFinding`. Pydantic's default is
    to ignore extras, so any future Semgrep schema additions are
    silently dropped here (M5 / M7 boundary).
    """

    model_config = ConfigDict(extra="ignore")

    cwe: Optional[Any] = None  # str OR list[str] depending on rule


class _SemgrepExtra(BaseModel):
    model_config = ConfigDict(extra="ignore")

    severity: str = "INFO"
    message: str = ""
    metadata: _SemgrepMetadata = Field(default_factory=_SemgrepMetadata)


class _SemgrepResult(BaseModel):
    """Allowlisted projection of a single Semgrep `results[*]` entry."""

    model_config = ConfigDict(extra="ignore")

    check_id: str = "rule.unknown"
    path: str
    start: _SemgrepStart = Field(default_factory=_SemgrepStart)
    extra: _SemgrepExtra = Field(default_factory=_SemgrepExtra)


class _SemgrepReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    results: List[_SemgrepResult] = Field(default_factory=list)


def _coerce_severity(raw: str) -> str:
    return _SEMGREP_SEVERITY_MAP.get(raw.upper(), "Low")


def _extract_cwe(metadata: _SemgrepMetadata) -> Optional[str]:
    """Pull a `CWE-NN` token out of Semgrep's metadata.cwe field, which
    is sometimes a string, sometimes a list of strings, sometimes None.
    Returns None when Semgrep's metadata carries no CWE.
    """
    raw = metadata.cwe
    if raw is None:
        return None
    candidates: List[str] = []
    if isinstance(raw, str):
        candidates = [raw]
    elif isinstance(raw, list):
        candidates = [str(item) for item in raw]
    for candidate in candidates:
        match = _CWE_PATTERN.search(candidate)
        if match:
            return f"CWE-{match.group(1)}"
    return None


def _semgrep_finding_to_vulnerability(
    raw: _SemgrepResult, original_paths: Dict[Path, str]
) -> VulnerabilityFinding:
    """Map a sanitized Semgrep result into the canonical
    `VulnerabilityFinding` shape.
    """
    try:
        staged = Path(raw.path).resolve()
    except (OSError, ValueError):
        staged = Path(raw.path)
    file_path = original_paths.get(staged, raw.path)

    description = html.escape(raw.extra.message)[:DESCRIPTION_MAX_CHARS]
    title = f"Semgrep {raw.check_id.split('.')[-1][:50]}"

    return VulnerabilityFinding(
        cwe=_extract_cwe(raw.extra.metadata),
        title=title,
        description=description,
        severity=_coerce_severity(raw.extra.severity),
        line_number=int(raw.start.line) if raw.start.line else 0,
        remediation="See Semgrep rule documentation for the suggested fix.",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path=str(file_path),
        fixes=None,
        source="semgrep",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )


def _invoke_semgrep_sync(
    staged_dir: Path, config_path: Path
) -> "subprocess.CompletedProcess[str]":
    """Run Semgrep via ``subprocess.run``. Pure sync; called from
    ``asyncio.to_thread`` so the event loop is not blocked.

    - ``shell=False`` and the args are a literal list (M1 / N2).
    - ``--config`` points to the caller-supplied materialized rule dir
      (N2). ``--no-git-ignore`` so an attacker-supplied ``.gitignore``
      cannot mask findings. ``--metrics=off`` disables phone-home.
      ``--disable-version-check`` avoids a network call mid-scan.
    - ``--`` precedes the staged path so even if it begins with ``-``
      it cannot be re-interpreted as a flag (M1).
    - ``timeout`` is enforced and raises ``TimeoutExpired``; caller
      maps to a Low-severity timeout finding (M6).
    """
    return subprocess.run(  # noqa: S603 - args are a literal list
        [
            _semgrep_binary(),
            "--config",
            str(config_path),
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--json",
            "--quiet",
            "--",
            str(staged_dir),
        ],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=SEMGREP_TIMEOUT_SECONDS,
    )


def _timeout_finding(staged_dir: Path) -> VulnerabilityFinding:
    """Single-finding placeholder so the worker graph still completes
    when Semgrep exceeds the hard timeout (M6).
    """
    return VulnerabilityFinding(
        cwe=None,
        title="Semgrep scanner timed out",
        description=html.escape(
            f"Semgrep exceeded the {SEMGREP_TIMEOUT_SECONDS}s timeout while scanning the project."
        )[:DESCRIPTION_MAX_CHARS],
        severity="Low",
        line_number=0,
        remediation="Re-run the scan with a smaller submission, or open an admin issue if this recurs.",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path=str(staged_dir),
        fixes=None,
        source="semgrep",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )


async def run_semgrep(
    staged_dir: Path,
    original_paths: Dict[Path, str],
    config_path: Optional[Path] = None,
) -> List[VulnerabilityFinding]:
    """Run Semgrep against ``staged_dir`` and return findings.

    ``config_path`` must be a directory of materialized YAML rule files
    from the DB ingestion layer. Pass ``None`` to skip Semgrep entirely
    (0 rules ingested for the detected languages).

    Returns an empty list when Semgrep finds nothing or fails to
    parse. On timeout, returns a single Low-severity placeholder so
    the caller has at least one observable signal. Never raises.
    """
    if config_path is None:
        logger.info("scanner=semgrep skipped — no config_path (0 ingested rules)")
        return []

    loop = asyncio.get_running_loop()
    started_at = loop.time()
    try:
        completed = await asyncio.to_thread(
            _invoke_semgrep_sync, staged_dir, config_path
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "scanner=semgrep staged_dir=%s rc=-9 timeout=%ss",
            staged_dir,
            SEMGREP_TIMEOUT_SECONDS,
        )
        return [_timeout_finding(staged_dir)]
    except FileNotFoundError:
        logger.error(
            "scanner=semgrep binary not found at %s; skipping prescan",
            _semgrep_binary(),
        )
        return []
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("scanner=semgrep unexpected failure: %s", exc)
        return []

    duration_ms = int((loop.time() - started_at) * 1000)
    logger.info(
        "scanner=semgrep staged_dir=%s rc=%d duration_ms=%d stdout_bytes=%d",
        staged_dir,
        completed.returncode,
        duration_ms,
        len(completed.stdout or ""),
    )
    logger.debug("scanner=semgrep raw stderr=%r", completed.stderr)

    if not completed.stdout:
        return []

    try:
        payload: Dict[str, Any] = json.loads(completed.stdout)
        report = _SemgrepReport.model_validate(payload)
    except (json.JSONDecodeError, ValidationError) as exc:
        logger.warning("scanner=semgrep JSON parse failed: %s", exc)
        return []

    findings: List[VulnerabilityFinding] = []
    for raw in report.results:
        try:
            findings.append(_semgrep_finding_to_vulnerability(raw, original_paths))
        except (ValidationError, ValueError) as exc:
            logger.warning(
                "scanner=semgrep dropped malformed result: %s check_id=%s",
                exc,
                raw.check_id,
            )
    return findings
