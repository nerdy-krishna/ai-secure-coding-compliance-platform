"""Bounded filesystem client for the networkless patch-validation service."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Mapping, Sequence

from app.shared.lib.patch_planner import PatchValidationCheck
from app.shared.lib.validation_sandbox_runner import PROFILE_COMMANDS, SCHEMA_VERSION

DEFAULT_JOB_DIR = Path("/var/lib/sccap-validation/jobs")


def select_validation_profiles(files: Mapping[str, str]) -> list[str]:
    """Select only fixed, image-supported profiles from repository shape."""
    paths = {path.replace("\\", "/").lower() for path in files}
    profiles: list[str] = []
    if any(path.endswith(".py") for path in paths):
        profiles.append("python_compile")
        if any(
            path.startswith("test") or "/test" in path or path.endswith("_test.py")
            for path in paths
        ) or paths.intersection({"pytest.ini", "tox.ini"}):
            profiles.append("python_pytest")
    if any(path.endswith((".js", ".mjs", ".cjs")) for path in paths):
        profiles.append("javascript_syntax")
    if any(path.endswith((".ts", ".tsx", ".mts", ".cts", ".jsx")) for path in paths):
        profiles.append("typescript_check")
    if any(path.endswith(".go") for path in paths):
        profiles.append("go_compile")
    if any(path.endswith(".java") for path in paths):
        profiles.append("java_compile")
    return profiles


def _write_atomic(path: Path, payload: dict) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        temporary = Path(handle.name)
    # The client and spool daemon share only gid 1001. The validation child
    # runs as gid 1002 and cannot traverse the spool directory.
    os.chmod(temporary, 0o660)  # nosec B103 - the spool daemon requires group access
    os.replace(temporary, path)


def _run_job(
    files: Mapping[str, str],
    profiles: Sequence[str],
    *,
    job_dir: Path,
    timeout_seconds: int,
) -> list[PatchValidationCheck]:
    if any(profile not in PROFILE_COMMANDS for profile in profiles):
        raise ValueError("validation profile is not allowlisted")
    if not job_dir.is_dir() or not (job_dir / ".ready").is_file():
        return [
            PatchValidationCheck(
                stage="sandbox",
                status="tool_missing",
                tool="sccap-patch-validator",
                detail="The networkless validation service is unavailable.",
            )
        ]
    job_id = uuid.uuid4().hex
    request_path = job_dir / f"{job_id}.request.json"
    response_path = job_dir / f"{job_id}.response.json"
    _write_atomic(
        request_path,
        {
            "schema_version": SCHEMA_VERSION,
            "files": dict(files),
            "profiles": list(profiles),
            "timeout_seconds": timeout_seconds,
        },
    )
    deadline = time.monotonic() + timeout_seconds + 10
    try:
        while time.monotonic() < deadline:
            if response_path.is_file():
                response = json.loads(response_path.read_text(encoding="utf-8"))
                checks = response.get("checks") if isinstance(response, dict) else None
                if not isinstance(checks, list):
                    raise ValueError("validation service returned an invalid response")
                return [
                    PatchValidationCheck.model_validate(
                        {
                            key: value
                            for key, value in check.items()
                            if key
                            in {
                                "stage",
                                "status",
                                "blocking",
                                "tool",
                                "profile",
                                "tool_version",
                                "completed_at",
                                "detail",
                                "return_code",
                                "duration_ms",
                                "output",
                            }
                        }
                    )
                    for check in checks
                ]
            time.sleep(0.05)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [
            PatchValidationCheck(
                stage="sandbox",
                status="infrastructure_error",
                tool="sccap-patch-validator",
                detail=f"Validation response failed with {type(exc).__name__}.",
            )
        ]
    finally:
        request_path.unlink(missing_ok=True)
        response_path.unlink(missing_ok=True)
    return [
        PatchValidationCheck(
            stage="sandbox",
            status="timeout",
            tool="sccap-patch-validator",
            detail="Validation service did not return before the job deadline.",
        )
    ]


async def run_sandbox_validation(
    files: Mapping[str, str],
    profiles: Sequence[str],
    *,
    job_dir: Path = DEFAULT_JOB_DIR,
    timeout_seconds: int = 60,
) -> list[PatchValidationCheck]:
    return await asyncio.to_thread(
        _run_job,
        files,
        profiles,
        job_dir=job_dir,
        timeout_seconds=timeout_seconds,
    )
