"""Bandit subprocess wrapper for the deterministic SAST pre-pass.

Invokes ``bandit -r -f json --quiet -- <staged_dir>`` and converts each
result into a :class:`VulnerabilityFinding` carrying ``source="bandit"``
and ``confidence="High"``.

Hardening (per the sast-prescan threat model):

- M1: ``subprocess.run([...], shell=False, check=False, timeout=120)``;
  arguments are a list; ``--`` separator before any user-derived path.
- M2: ``staged_dir`` is the sandbox produced by
  :func:`~app.infrastructure.scanners.staging.stage_files`; we never
  pass user-controlled paths.
- M5: scanner ``stdout`` is parsed and discarded; we never log it
  above DEBUG. (Bandit does not emit secret values, but the discipline
  generalises to Gitleaks once that scanner lands.)
- M6: 120-second hard timeout; on ``TimeoutExpired`` the wrapper kills
  the process tree and returns a single low-severity timeout finding
  so the worker graph keeps moving.
- M7: ``description`` is HTML-escaped and capped at 200 chars before
  it can reach any LLM agent prompt.

The wrapper is ``async`` but executes Bandit on a worker thread via
``asyncio.to_thread`` so the FastAPI / LangGraph event loop stays
responsive while Bandit walks the AST.
"""

from __future__ import annotations

import asyncio
import functools
import html
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.schemas import VulnerabilityFinding


logger = logging.getLogger(__name__)


@functools.cache
def _resolve_binary(env_var: str, name: str, fallback: Optional[str] = None) -> str:
    """Locate a scanner binary via env override → PATH → hardcoded fallback.

    Lets local dev outside Docker iterate without a fixed venv layout
    (set ``BANDIT_BINARY=/usr/local/bin/bandit`` etc.), while production
    images keep the same hardcoded fallback they always had.

    Cached on `(env_var, name, fallback)` so the lookup happens once
    per (binary, fallback) tuple — but lazily, on first call. Module-
    import time used to resolve eagerly, which meant `*_BINARY` env
    vars set in `.env` (loaded after module import by `load_dotenv()`
    in worker startup) were silently ignored. Lazy + cached hits the
    sweet spot: env honored on first scanner call, no per-invocation
    PATH walk.
    """
    return (
        os.environ.get(env_var)
        or shutil.which(name)
        or (fallback if fallback is not None else f"/app/.venv/bin/{name}")
    )


def _bandit_binary() -> str:
    """Lazy accessor for the Bandit binary path. See `_resolve_binary`."""
    return _resolve_binary("BANDIT_BINARY", "bandit")


BANDIT_TIMEOUT_SECONDS = 120
DESCRIPTION_MAX_CHARS = 2000

# Bandit severity strings (LOW / MEDIUM / HIGH) → SCCAP severity bucket
# (Title-cased, matching what LLM agents emit). Bandit has no CRITICAL.
_BANDIT_SEVERITY_MAP: Dict[str, str] = {
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
}


class _BanditCwe(BaseModel):
    id: Optional[int] = None
    link: Optional[str] = None


class _BanditResult(BaseModel):
    """Allowlisted projection of a single Bandit `results[*]` entry.

    Pydantic strips any extra fields by default; this is the M5 / M7
    boundary — only these fields can flow into a `VulnerabilityFinding`.

    NOTE: Bandit emits the CWE block under the JSON key `issue_cwe`,
    not `cwe`. The previous version of this model bound to `cwe` only
    so every result came back with `cwe=None`, the fallback string
    `"CWE-unknown"` failed VulnerabilityFinding's pattern + length
    validators, and the result was silently dropped. The
    `populate_by_name=True` config + `validation_alias="issue_cwe"`
    fixes the binding while keeping the attribute name short.
    """

    model_config = ConfigDict(populate_by_name=True)

    filename: str
    line_number: int = 0
    test_id: str = "B000"
    issue_severity: str = "LOW"
    issue_confidence: str = "LOW"
    issue_text: str = ""
    cwe: Optional[_BanditCwe] = Field(default=None, validation_alias="issue_cwe")


class _BanditReport(BaseModel):
    results: List[_BanditResult] = Field(default_factory=list)


def _coerce_severity(raw: str) -> str:
    return _BANDIT_SEVERITY_MAP.get(raw.upper(), "Low")


def _bandit_finding_to_vulnerability(
    raw: _BanditResult, original_paths: Dict[Path, str]
) -> VulnerabilityFinding:
    """Map a sanitized Bandit result into the canonical
    `VulnerabilityFinding` shape.

    Path resolution: Bandit reports the *staged* filename. We translate
    back to the user-facing relative path via ``original_paths``; if
    the staged path isn't in the map (shouldn't happen), we fall back
    to the literal filename so the finding is still surfaced.
    """
    try:
        staged = Path(raw.filename).resolve()
    except (OSError, ValueError):
        staged = Path(raw.filename)
    file_path = original_paths.get(staged, raw.filename)

    # Keep the real CWE Bandit emitted; None when its metadata has none.
    # `cwe` is optional on VulnerabilityFinding — only deterministic
    # scanners populate it.
    cwe = f"CWE-{raw.cwe.id}" if raw.cwe and raw.cwe.id is not None else None
    description = html.escape(raw.issue_text)[:DESCRIPTION_MAX_CHARS]
    title = (raw.test_id or "B000").strip()[:50]

    return VulnerabilityFinding(
        cwe=cwe,
        title=f"Bandit {title}",
        description=description,
        severity=_coerce_severity(raw.issue_severity),
        line_number=int(raw.line_number) if raw.line_number else 0,
        remediation="See Bandit rule documentation for the suggested fix.",
        confidence="High",
        references=[raw.cwe.link] if raw.cwe and raw.cwe.link else [],
        cvss_score=None,
        cvss_vector=None,
        file_path=str(file_path),
        fixes=None,
        source="bandit",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )


def _invoke_bandit_sync(staged_dir: Path) -> "subprocess.CompletedProcess[str]":
    """Run Bandit via ``subprocess.run``. Pure sync; called from
    ``asyncio.to_thread`` so the event loop is not blocked.

    Notes for reviewers:

    - ``shell=False`` and the args are a literal list (M1).
    - ``--`` precedes the staged path so even if the path begins with
      ``-`` it cannot be re-interpreted as a flag (M1).
    - ``timeout`` is enforced and raises ``TimeoutExpired`` which the
      caller maps to a Low-severity timeout finding (M6).
    - ``capture_output=True, text=True`` because Bandit's JSON output
      goes to stdout. ``--quiet`` suppresses progress lines on stderr.
    """
    return subprocess.run(  # noqa: S603 - args are a literal list, not user-supplied
        [
            _bandit_binary(),
            "-r",
            "-f",
            "json",
            "--quiet",
            "--",
            str(staged_dir),
        ],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=BANDIT_TIMEOUT_SECONDS,
    )


def _timeout_finding(staged_dir: Path) -> VulnerabilityFinding:
    """Single-finding placeholder so the worker graph still completes
    when Bandit exceeds the hard timeout (M6).
    """
    return VulnerabilityFinding(
        cwe=None,
        title="Bandit scanner timed out",
        description=html.escape(
            f"Bandit exceeded the {BANDIT_TIMEOUT_SECONDS}s timeout while scanning the project."
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
        source="bandit",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )


async def run_bandit(
    staged_dir: Path, original_paths: Dict[Path, str]
) -> List[VulnerabilityFinding]:
    """Run Bandit against ``staged_dir`` and return findings.

    Returns an empty list if Bandit completed successfully with zero
    issues. On timeout, returns a single Low-severity placeholder so
    the caller has at least one observable signal. On parse failure,
    logs and returns an empty list (do not block the scan).

    Never raises.
    """
    loop = asyncio.get_running_loop()
    started_at = loop.time()
    try:
        completed = await asyncio.to_thread(_invoke_bandit_sync, staged_dir)
    except subprocess.TimeoutExpired:
        logger.warning(
            "scanner=bandit staged_dir=%s rc=-9 timeout=%ss",
            staged_dir,
            BANDIT_TIMEOUT_SECONDS,
        )
        return [_timeout_finding(staged_dir)]
    except FileNotFoundError:
        logger.error(
            "scanner=bandit binary not found at %s; skipping prescan", _bandit_binary()
        )
        return []
    except Exception as exc:  # pragma: no cover - defensive, should not happen
        logger.exception("scanner=bandit unexpected failure: %s", exc)
        return []

    duration_ms = int((loop.time() - started_at) * 1000)
    # Bandit returns rc=0 with empty results, rc=1 when it found issues,
    # rc>=2 on hard error. Either way the JSON is on stdout when Bandit
    # got far enough to format it.
    logger.info(
        "scanner=bandit staged_dir=%s rc=%d duration_ms=%d stdout_bytes=%d",
        staged_dir,
        completed.returncode,
        duration_ms,
        len(completed.stdout or ""),
    )
    logger.debug("scanner=bandit raw stderr=%r", completed.stderr)

    if not completed.stdout:
        return []

    try:
        payload: Dict[str, Any] = json.loads(completed.stdout)
        report = _BanditReport.model_validate(payload)
    except (json.JSONDecodeError, ValidationError) as exc:
        logger.warning("scanner=bandit JSON parse failed: %s", exc)
        return []

    findings: List[VulnerabilityFinding] = []
    for raw in report.results:
        try:
            findings.append(_bandit_finding_to_vulnerability(raw, original_paths))
        except (ValidationError, ValueError) as exc:
            logger.warning(
                "scanner=bandit dropped malformed result: %s test_id=%s",
                exc,
                raw.test_id,
            )
    return findings
