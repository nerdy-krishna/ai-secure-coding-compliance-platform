"""Request and optionally wait for a graceful worker drain."""

from __future__ import annotations

import argparse
import os
import tempfile
import time
from pathlib import Path

from app.config.config import settings

_WORKER_RUNTIME_ROOT = (Path(tempfile.gettempdir()) / "sccap-worker").resolve()


def _safe_runtime_path(raw: str) -> Path:
    path = Path(raw).resolve()
    if path.parent != _WORKER_RUNTIME_ROOT:
        raise ValueError(f"worker drain files must stay under {_WORKER_RUNTIME_ROOT}/")
    return path


def request_drain(*, wait: bool, timeout: int) -> bool:
    requested = _safe_runtime_path(settings.WORKER_DRAIN_FILE)
    drained = _safe_runtime_path(settings.WORKER_DRAINED_FILE)
    requested.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        drained.unlink(missing_ok=True)
        requested.touch(mode=0o600, exist_ok=True)
    except OSError:
        return False
    if not wait:
        return True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if drained.exists():
            return True
        time.sleep(1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait", action="store_true")
    parser.add_argument(
        "--timeout",
        type=int,
        default=min(settings.WORKER_DRAIN_TIMEOUT_SECONDS, 570),
    )
    args = parser.parse_args()
    timeout = max(1, min(int(args.timeout), 570))
    return (
        os.EX_OK if request_drain(wait=args.wait, timeout=timeout) else os.EX_TEMPFAIL
    )


if __name__ == "__main__":
    raise SystemExit(main())
