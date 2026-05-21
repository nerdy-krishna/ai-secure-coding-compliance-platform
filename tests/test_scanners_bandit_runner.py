"""Unit tests for the Bandit subprocess wrapper.

These tests run inside Docker because Bandit must actually execute on
real files (M1 + M6 mitigations are about subprocess behavior). The
"timeout" and "binary missing" branches are exercised via monkeypatch
so we don't need to rely on platform-specific signals.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest

from app.infrastructure.scanners import bandit_runner
from app.infrastructure.scanners.bandit_runner import (
    BANDIT_TIMEOUT_SECONDS,
    DESCRIPTION_MAX_CHARS,
    run_bandit,
)
from app.infrastructure.scanners.staging import stage_files


pytestmark = pytest.mark.asyncio


async def test_bandit_finds_known_high_severity_issue():
    """A canonical `subprocess.call(..., shell=True)` triggers Bandit's
    B602 rule. The wrapper must surface it as a `source="bandit"`
    finding with `confidence="High"` and a CWE attribution.
    """
    files = {
        "vulnerable.py": (
            "import subprocess\n"
            "def run(user_input):\n"
            "    subprocess.call(user_input, shell=True)\n"
        )
    }
    with stage_files(files) as (staged_dir, original_paths):
        findings = await run_bandit(staged_dir, original_paths)
    assert findings, "Bandit should flag subprocess shell=True"
    bandit_finding = next(f for f in findings if f.title.startswith("Bandit B"))
    assert bandit_finding.source == "bandit"
    assert bandit_finding.confidence == "High"
    assert bandit_finding.severity in {"High", "Medium", "Low"}
    assert bandit_finding.file_path == "vulnerable.py"


async def test_bandit_returns_empty_for_clean_code():
    files = {"clean.py": "x = 1 + 1\n"}
    with stage_files(files) as (staged_dir, original_paths):
        findings = await run_bandit(staged_dir, original_paths)
    assert findings == []


async def test_bandit_timeout_returns_low_severity_placeholder(monkeypatch, caplog):
    def _raise_timeout(_cmd, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="bandit", timeout=BANDIT_TIMEOUT_SECONDS)

    monkeypatch.setattr(bandit_runner, "_invoke_bandit_sync", _raise_timeout)
    findings = await run_bandit(Path("/tmp/staged"), original_paths={})
    assert len(findings) == 1
    assert findings[0].severity == "Low"
    assert findings[0].source == "bandit"
    assert "timed out" in findings[0].title.lower()
    assert any("timeout" in r.getMessage() for r in caplog.records)


async def test_bandit_binary_missing_returns_empty(monkeypatch):
    def _raise_missing(_cmd, **_kwargs):
        raise FileNotFoundError("bandit not installed")

    monkeypatch.setattr(bandit_runner, "_invoke_bandit_sync", _raise_missing)
    findings = await run_bandit(Path("/tmp/staged"), original_paths={})
    assert findings == []


async def test_bandit_description_is_html_escaped_and_truncated():
    """Crafted source whose attacker-influenced finding text contains
    HTML metachars must be escaped and truncated before it can ride
    into a downstream LLM agent prompt (M7).
    """
    # `assert` statements get a very short Bandit message — instead use
    # a long path-like string in a hardcoded password (B105) trigger so
    # the resulting `issue_text` is non-trivial.
    files = {
        "secret.py": ('PASSWORD = "<script>alert(1)</script>" + ("A" * 250)\nx = 1\n')
    }
    with stage_files(files) as (staged_dir, original_paths):
        findings = await run_bandit(staged_dir, original_paths)
    if not findings:
        pytest.skip("Bandit did not flag the synthetic test input")
    assert all(len(f.description) <= DESCRIPTION_MAX_CHARS for f in findings)
    # No raw `<script>` survives into description (HTML-escape applied).
    for f in findings:
        assert "<script>" not in f.description


async def test_bandit_runner_is_async_safe():
    """Two concurrent invocations on disjoint sandboxes must not
    interfere with each other (M3-style isolation).
    """
    files_a = {"a.py": "import subprocess\nsubprocess.call('ls', shell=True)\n"}
    files_b = {"b.py": "y = 1 + 1\n"}
    with stage_files(files_a) as (dir_a, map_a), stage_files(files_b) as (dir_b, map_b):
        results_a, results_b = await asyncio.gather(
            run_bandit(dir_a, map_a),
            run_bandit(dir_b, map_b),
        )
    assert results_a, "Bandit should still flag the vuln in tenant A"
    # Tenant B is clean; nothing for it.
    assert results_b == []
