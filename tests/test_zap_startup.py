"""ZAP startup: the argument contract and the failure modes.

The failure an operator saw was "ZAP daemon did not become ready" after a long wait,
with nothing to explain it. The cause was an unsupported CLI option — the daemon
exited immediately and the readiness loop kept polling a port nothing was listening
on. These tests pin down the command line and the diagnostics.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest

from app.pentest.tools import zap_tool
from app.pentest.tools.base import RunContext


def test_port_is_passed_as_a_separate_argument():
    command = zap_tool.zap_command(8090)

    assert "-port" in command
    assert command[command.index("-port") + 1] == "8090"
    assert not any(argument.startswith("-port=") for argument in command), (
        "ZAP rejects '-port=…' as an unsupported option and exits before binding"
    )


def test_startup_update_checks_are_disabled():
    command = " ".join(zap_tool.zap_command(8090))

    assert "startup.checkForUpdates=false" in command
    assert "startup.downloadAddons=false" in command


def test_missing_binary_is_reported_clearly(monkeypatch, tmp_path):
    monkeypatch.setattr(zap_tool, "ZAP_SH", str(tmp_path / "nope" / "zap.sh"))
    daemon = zap_tool.ZapDaemon(8099)

    with pytest.raises(RuntimeError) as excinfo:
        asyncio.run(daemon.start())

    assert "not installed" in str(excinfo.value)
    assert "zap.sh" in str(excinfo.value)


def test_early_exit_reports_the_log_not_a_timeout(monkeypatch, tmp_path):
    fake_sh = tmp_path / "zap.sh"
    fake_sh.write_text("#!/bin/sh\nexit 1\n")
    fake_sh.chmod(0o755)
    monkeypatch.setattr(zap_tool, "ZAP_SH", str(fake_sh))
    monkeypatch.setattr(zap_tool, "ZAP_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(zap_tool, "ZAP_READY_SECONDS", 5)

    class DeadProcess:
        returncode = 1

        async def wait(self):
            return 1

    async def fake_exec(*_args, **_kwargs):
        # Simulate the daemon writing its complaint and exiting at once.
        with open(f"/tmp/zap-{8098}.log", "w") as handle:
            handle.write("Unsupported option '-port=8098'.\njava.lang.Exception\n")
        return DeadProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    daemon = zap_tool.ZapDaemon(8098)

    with pytest.raises(RuntimeError) as excinfo:
        asyncio.run(daemon.start())

    message = str(excinfo.value)
    assert "exited with code 1" in message
    assert "Unsupported option" in message, "the daemon's own words must reach the operator"


def test_a_failed_start_is_remembered_for_the_run(monkeypatch):
    """A four-minute stall must not be repeated on every turn."""
    ctx = RunContext(
        run_id=uuid.uuid4(),
        target=SimpleNamespace(url="http://example.com", host="example.com"),
        box_type="black",
    )
    ctx.zap_unavailable = "ZAP is not installed at /zap/zap.sh in this image"

    with pytest.raises(RuntimeError) as excinfo:
        zap_tool._session(ctx)

    assert "not installed" in str(excinfo.value)
