"""Unit tests for the Semgrep subprocess wrapper.

Subprocess invocation is mocked via monkeypatch so these tests don't
depend on the actual `semgrep` binary being present in the test
container — the Dockerfile installs it in `/opt/semgrep-venv`, but we
run pytest in the api container which doesn't have the worker stage.
The "actual binary works" claim is verified separately by the
`docker compose build worker` gate in the verifier matrix.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pathlib import Path as _Path

from app.infrastructure.scanners import semgrep_runner
from app.infrastructure.scanners.semgrep_runner import (
    DESCRIPTION_MAX_CHARS,
    SEMGREP_TIMEOUT_SECONDS,
    run_semgrep,
)

_FAKE_CONFIG = _Path("/tmp/fake-rules")


pytestmark = pytest.mark.asyncio


def _fake_completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["semgrep"], returncode=returncode, stdout=stdout, stderr=""
    )


def _semgrep_payload(*results) -> str:
    return json.dumps({"results": list(results)})


async def test_semgrep_finds_known_issue(monkeypatch):
    """A canonical Semgrep result must surface as a `source="semgrep"`
    finding with `confidence="High"` and parsed CWE.
    """
    payload = _semgrep_payload(
        {
            "check_id": "javascript.lang.security.audit.path-traversal",
            "path": "/tmp/staged/handlers/user.js",
            "start": {"line": 42},
            "extra": {
                "severity": "ERROR",
                "message": "Possible path traversal via user input",
                "metadata": {"cwe": ["CWE-22: Path Traversal"]},
            },
        }
    )
    monkeypatch.setattr(
        semgrep_runner,
        "_invoke_semgrep_sync",
        lambda _d, _cfg: _fake_completed(payload),
    )
    findings = await run_semgrep(
        Path("/tmp/staged"),
        original_paths={Path("/tmp/staged/handlers/user.js"): "handlers/user.js"},
        config_path=_FAKE_CONFIG,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "semgrep"
    assert f.confidence == "High"
    assert f.severity == "High"
    assert f.cwe == "CWE-22"
    assert f.file_path == "handlers/user.js"
    assert f.line_number == 42


async def test_semgrep_returns_empty_for_clean_payload(monkeypatch):
    monkeypatch.setattr(
        semgrep_runner,
        "_invoke_semgrep_sync",
        lambda _d, _cfg: _fake_completed(_semgrep_payload()),
    )
    assert (
        await run_semgrep(
            Path("/tmp/staged"), original_paths={}, config_path=_FAKE_CONFIG
        )
        == []
    )


async def test_semgrep_returns_empty_when_no_config_path():
    """If config_path is None (0 ingested rules), run_semgrep must return [] without invoking semgrep."""
    assert (
        await run_semgrep(Path("/tmp/staged"), original_paths={}, config_path=None)
        == []
    )


async def test_semgrep_timeout_returns_low_severity_placeholder(monkeypatch, caplog):
    def _raise(_d, _cfg):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=SEMGREP_TIMEOUT_SECONDS)

    monkeypatch.setattr(semgrep_runner, "_invoke_semgrep_sync", _raise)
    findings = await run_semgrep(
        Path("/tmp/staged"), original_paths={}, config_path=_FAKE_CONFIG
    )
    assert len(findings) == 1
    assert findings[0].severity == "Low"
    assert findings[0].source == "semgrep"
    assert any("timeout" in r.getMessage() for r in caplog.records)


async def test_semgrep_description_is_html_escaped_and_truncated(monkeypatch):
    """Crafted source whose Semgrep `extra.message` contains HTML
    metachars must be escaped and truncated before riding into a
    downstream LLM agent prompt (M7 / N6).
    """
    long_message = "<script>alert(1)</script> " + ("A" * 500)
    payload = _semgrep_payload(
        {
            "check_id": "test.injection",
            "path": "/tmp/staged/x.py",
            "start": {"line": 1},
            "extra": {
                "severity": "WARNING",
                "message": long_message,
                "metadata": {"cwe": "CWE-79"},
            },
        }
    )
    monkeypatch.setattr(
        semgrep_runner,
        "_invoke_semgrep_sync",
        lambda _d, _cfg: _fake_completed(payload),
    )
    findings = await run_semgrep(
        Path("/tmp/staged"), original_paths={}, config_path=_FAKE_CONFIG
    )
    assert len(findings) == 1
    assert len(findings[0].description) <= DESCRIPTION_MAX_CHARS
    assert "<script>" not in findings[0].description
    assert "&lt;script&gt;" in findings[0].description


async def test_semgrep_binary_missing_returns_empty(monkeypatch):
    def _raise(_d, _cfg):
        raise FileNotFoundError("semgrep not installed")

    monkeypatch.setattr(semgrep_runner, "_invoke_semgrep_sync", _raise)
    assert (
        await run_semgrep(
            Path("/tmp/staged"), original_paths={}, config_path=_FAKE_CONFIG
        )
        == []
    )
