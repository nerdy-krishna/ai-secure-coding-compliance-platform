"""Registry and runner for subprocesses owned by a running scan.

Scanner calls remain synchronous inside ``asyncio.to_thread``. This registry lets
the worker cancellation watcher terminate their process groups immediately even
though cancelling the awaiting coroutine alone cannot stop a Python worker thread.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import os
import signal
import subprocess
import threading
from typing import Any, Iterator, Optional, Sequence


_scan_scope: ContextVar[Optional[str]] = ContextVar(
    "owned_subprocess_scan_id", default=None
)
_registry_lock = threading.Lock()
_registry: dict[str, set[subprocess.Popen[Any]]] = {}


@contextmanager
def scan_process_scope(scan_id: object) -> Iterator[None]:
    token = _scan_scope.set(str(scan_id))
    try:
        yield
    finally:
        _scan_scope.reset(token)


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:  # pragma: no cover - production workers are Linux
            process.terminate()
        process.wait(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:  # pragma: no cover
                process.kill()
        except OSError:
            pass


def terminate_owned_processes(scan_id: object) -> int:
    """Terminate every currently registered process group for ``scan_id``."""
    key = str(scan_id)
    with _registry_lock:
        processes = tuple(_registry.get(key, ()))
    for process in processes:
        _terminate_process_group(process)
    return len(processes)


def run_owned_subprocess(
    args: Sequence[str],
    *,
    shell: bool = False,
    check: bool = False,
    capture_output: bool = False,
    text: bool = False,
    timeout: Optional[float] = None,
    cwd: Optional[str | os.PathLike[str]] = None,
    env: Optional[dict[str, str]] = None,
) -> subprocess.CompletedProcess[Any]:
    """A narrow ``subprocess.run`` equivalent with cancellation ownership."""
    if shell:
        raise ValueError("Owned subprocesses must not use a shell")
    stdout = subprocess.PIPE if capture_output else None
    stderr = subprocess.PIPE if capture_output else None
    process = subprocess.Popen(  # noqa: S603 - callers supply allowlisted binaries
        list(args),
        shell=False,
        stdout=stdout,
        stderr=stderr,
        text=text,
        cwd=cwd,
        env=env,
        start_new_session=True,
    )
    scan_id = _scan_scope.get()
    if scan_id is not None:
        with _registry_lock:
            _registry.setdefault(scan_id, set()).add(process)
    try:
        try:
            output, errors = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            output, errors = process.communicate()
            raise subprocess.TimeoutExpired(
                list(args), timeout, output=output, stderr=errors
            )
        completed = subprocess.CompletedProcess(
            list(args), process.returncode, output, errors
        )
        if check:
            completed.check_returncode()
        return completed
    finally:
        if scan_id is not None:
            with _registry_lock:
                owned = _registry.get(scan_id)
                if owned is not None:
                    owned.discard(process)
                    if not owned:
                        _registry.pop(scan_id, None)
