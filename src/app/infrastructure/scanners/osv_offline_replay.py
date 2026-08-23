"""Strict, immutable OSV advisory replay for patch promotion.

Prescan remains fail-soft, but remediation promotion must never turn an OSV
failure into a clean result or query the mutable OSV API.  Operators provide a
read-only snapshot directory through ``OSV_OFFLINE_SNAPSHOT_DIR`` containing
``snapshot.json`` and OSV-Scanner's normal ``osv-scanner/<ecosystem>/all.zip``
cache layout.  The manifest binds every database file by path, size, and
SHA-256.  It is verified immediately before and after the subprocess to catch
replacement during a replay.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.scanners.osv_runner import (
    OSV_TIMEOUT_SECONDS,
    _osv_binary,
    _redact_stderr,
    parse_osv_findings_report,
)
from app.shared.lib.owned_subprocess import run_owned_subprocess

SNAPSHOT_ENV = "OSV_OFFLINE_SNAPSHOT_DIR"
SNAPSHOT_MANIFEST = "snapshot.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SNAPSHOT_FILES = 256
MAX_SNAPSHOT_FILE_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_REPLAY_REPORT_BYTES = 5 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")


class OfflineSnapshotError(RuntimeError):
    """A fail-closed snapshot or replay failure with a stable reason code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _SnapshotFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=240)
    size_bytes: int = Field(ge=1, le=MAX_SNAPSHOT_FILE_BYTES)
    sha256: str


class _SnapshotManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    snapshot_id: str = Field(min_length=1, max_length=128)
    created_at: str = Field(min_length=1, max_length=64)
    files: list[_SnapshotFile] = Field(min_length=1, max_length=MAX_SNAPSHOT_FILES)


@dataclass(frozen=True)
class OfflineOSVSnapshot:
    root: Path
    snapshot_id: str
    created_at: str
    manifest_sha256: str
    database_sha256: str
    file_count: int
    total_bytes: int

    def provenance(self) -> dict[str, Any]:
        return {
            "mode": "offline_snapshot",
            "immutable": True,
            "status": "verified",
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at,
            "manifest_sha256": self.manifest_sha256,
            "database_sha256": self.database_sha256,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True)
class OfflineOSVReplayResult:
    status: Literal["passed", "tool_missing", "timeout", "infrastructure_error"]
    detail: str
    findings: list[VulnerabilityFinding]
    duration_ms: int
    return_code: int | None = None
    raw_report: Dict[str, Any] | None = None
    snapshot_provenance: Dict[str, Any] | None = None


def _safe_database_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or "\\" in relative:
        raise OfflineSnapshotError("snapshot_path_invalid")
    # OSV-Scanner v2 reads this exact cache layout.  Limiting manifests to
    # database archives avoids binding arbitrary operator files as evidence.
    if len(pure.parts) != 3 or pure.parts[0] != "osv-scanner":
        raise OfflineSnapshotError("snapshot_path_invalid")
    if not pure.parts[1] or pure.parts[2] != "all.zip":
        raise OfflineSnapshotError("snapshot_path_invalid")
    candidate = root.joinpath(*pure.parts)
    cursor = root
    for part in pure.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise OfflineSnapshotError("snapshot_symlink_rejected")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise OfflineSnapshotError("snapshot_file_unavailable") from None
    if not resolved.is_file():
        raise OfflineSnapshotError("snapshot_file_unavailable")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise OfflineSnapshotError("snapshot_file_unavailable") from None
    return digest.hexdigest()


def load_offline_snapshot(root: Path | None = None) -> OfflineOSVSnapshot:
    """Load and verify a bounded, read-only advisory snapshot manifest."""
    configured = str(root) if root is not None else os.getenv(SNAPSHOT_ENV, "")
    if not configured.strip():
        raise OfflineSnapshotError("snapshot_unconfigured")
    snapshot_root = Path(configured).resolve()
    if os.access(snapshot_root, os.W_OK):
        raise OfflineSnapshotError("snapshot_not_read_only")
    manifest_path = snapshot_root / SNAPSHOT_MANIFEST
    if manifest_path.is_symlink():
        raise OfflineSnapshotError("snapshot_symlink_rejected")
    try:
        stat = manifest_path.stat()
    except OSError:
        raise OfflineSnapshotError("snapshot_manifest_unavailable") from None
    if not manifest_path.is_file() or stat.st_size > MAX_MANIFEST_BYTES:
        raise OfflineSnapshotError("snapshot_manifest_invalid")
    # A worker-writable manifest/database is not immutable evidence.  A
    # root-owned 0644 file on a read-only mount remains non-writable to uid 1001.
    if os.access(manifest_path, os.W_OK):
        raise OfflineSnapshotError("snapshot_not_read_only")
    try:
        manifest_bytes = manifest_path.read_bytes()
        raw = json.loads(manifest_bytes)
        manifest = _SnapshotManifest.model_validate(raw)
    except (OSError, ValueError, ValidationError):
        raise OfflineSnapshotError("snapshot_manifest_invalid") from None
    if not _SNAPSHOT_ID_RE.fullmatch(manifest.snapshot_id):
        raise OfflineSnapshotError("snapshot_id_invalid")

    seen: set[str] = set()
    canonical_files: list[dict[str, Any]] = []
    total_bytes = 0
    for entry in sorted(manifest.files, key=lambda item: item.path):
        if entry.path in seen:
            raise OfflineSnapshotError("snapshot_duplicate_path")
        seen.add(entry.path)
        if not _SHA256_RE.fullmatch(entry.sha256):
            raise OfflineSnapshotError("snapshot_digest_invalid")
        path = _safe_database_path(snapshot_root, entry.path)
        try:
            size = path.stat().st_size
        except OSError:
            raise OfflineSnapshotError("snapshot_file_unavailable") from None
        total_bytes += size
        if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES:
            raise OfflineSnapshotError("snapshot_size_limit_exceeded")
        if size != entry.size_bytes or _sha256_file(path) != entry.sha256:
            raise OfflineSnapshotError("snapshot_content_mismatch")
        if os.access(path, os.W_OK):
            raise OfflineSnapshotError("snapshot_not_read_only")
        canonical_files.append(entry.model_dump(mode="json"))

    canonical = json.dumps(
        canonical_files, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return OfflineOSVSnapshot(
        root=snapshot_root,
        snapshot_id=manifest.snapshot_id,
        created_at=manifest.created_at,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        database_sha256=hashlib.sha256(canonical).hexdigest(),
        file_count=len(canonical_files),
        total_bytes=total_bytes,
    )


def advisory_provenance() -> dict[str, Any]:
    """Return current snapshot evidence without making configuration fatal."""
    if not os.getenv(SNAPSHOT_ENV, "").strip():
        return {
            "mode": "live_osv_api",
            "immutable": False,
            "status": "degraded",
            "reason": "advisory_snapshot_identifier_unavailable",
        }
    try:
        return load_offline_snapshot().provenance()
    except OfflineSnapshotError as exc:
        return {
            "mode": "offline_snapshot",
            "immutable": False,
            "status": "degraded",
            "reason": exc.code,
        }


def _subprocess_environment(snapshot: OfflineOSVSnapshot) -> dict[str, str]:
    """Provide only non-secret runtime settings; proxy credentials are omitted."""
    return {
        "HOME": "/tmp",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GOMEMLIMIT": "384MiB",
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(snapshot.root),
    }


def _run_replay_subprocess(
    binary: str,
    staged_dir: Path,
    output_path: Path,
    snapshot: OfflineOSVSnapshot,
) -> tuple[int, str]:
    completed = run_owned_subprocess(
        [
            binary,
            "scan",
            "source",
            "--recursive",
            "--offline",
            "--offline-vulnerabilities",
            "--no-resolve",
            "--format",
            "json",
            "--output-file",
            str(output_path),
            str(staged_dir),
        ],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=OSV_TIMEOUT_SECONDS,
        cwd=output_path.parent,
        env=_subprocess_environment(snapshot),
    )
    return completed.returncode, _redact_stderr(completed.stderr or "")


async def run_offline_osv_replay(
    staged_dir: Path,
    original_paths: Mapping[Path, str],
) -> OfflineOSVReplayResult:
    """Replay OSV against an immutable local database, never a live service."""
    started = time.monotonic()
    try:
        snapshot = load_offline_snapshot()
    except OfflineSnapshotError as exc:
        return OfflineOSVReplayResult(
            status=(
                "tool_missing"
                if exc.code
                in {"snapshot_unconfigured", "snapshot_manifest_unavailable"}
                else "infrastructure_error"
            ),
            detail=f"Immutable OSV advisory snapshot unavailable ({exc.code}).",
            findings=[],
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    binary = _osv_binary()
    binary_path = Path(binary)
    if not binary or not binary_path.is_file() or not os.access(binary_path, os.X_OK):
        return OfflineOSVReplayResult(
            status="tool_missing",
            detail="Pinned OSV-Scanner executable is unavailable.",
            findings=[],
            duration_ms=int((time.monotonic() - started) * 1000),
            snapshot_provenance=snapshot.provenance(),
        )

    with tempfile.TemporaryDirectory(prefix="osv-offline-replay-") as tmp:
        output_path = Path(tmp) / "results.json"
        try:
            return_code, _stderr = await asyncio.to_thread(
                _run_replay_subprocess,
                binary,
                staged_dir,
                output_path,
                snapshot,
            )
        except subprocess.TimeoutExpired:
            return OfflineOSVReplayResult(
                status="timeout",
                detail=f"Offline OSV replay exceeded {OSV_TIMEOUT_SECONDS} seconds.",
                findings=[],
                duration_ms=int((time.monotonic() - started) * 1000),
                snapshot_provenance=snapshot.provenance(),
            )
        except (OSError, subprocess.SubprocessError):
            return OfflineOSVReplayResult(
                status="infrastructure_error",
                detail="Offline OSV replay could not start.",
                findings=[],
                duration_ms=int((time.monotonic() - started) * 1000),
                snapshot_provenance=snapshot.provenance(),
            )

        if return_code not in (0, 1):
            return OfflineOSVReplayResult(
                status="infrastructure_error",
                detail=f"Offline OSV replay exited with code {return_code}.",
                findings=[],
                duration_ms=int((time.monotonic() - started) * 1000),
                return_code=return_code,
                snapshot_provenance=snapshot.provenance(),
            )
        try:
            report_size = output_path.stat().st_size
            if report_size > MAX_REPLAY_REPORT_BYTES:
                raise OfflineSnapshotError("replay_report_size_limit_exceeded")
            raw = json.loads(output_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise OfflineSnapshotError("replay_report_invalid")
            findings = parse_osv_findings_report(raw, original_paths)
            # Re-hash the full manifest after matching to close the mutation
            # window between validation and subprocess completion.
            verified_after = load_offline_snapshot(snapshot.root)
            if verified_after.database_sha256 != snapshot.database_sha256:
                raise OfflineSnapshotError("snapshot_changed_during_replay")
        except (OSError, ValueError, ValidationError, OfflineSnapshotError) as exc:
            code = (
                exc.code
                if isinstance(exc, OfflineSnapshotError)
                else "replay_report_invalid"
            )
            return OfflineOSVReplayResult(
                status="infrastructure_error",
                detail=f"Offline OSV replay evidence is invalid ({code}).",
                findings=[],
                duration_ms=int((time.monotonic() - started) * 1000),
                return_code=return_code,
                snapshot_provenance=snapshot.provenance(),
            )

    return OfflineOSVReplayResult(
        status="passed",
        detail=(
            f"Offline OSV replay completed with {len(findings)} finding(s) "
            f"using snapshot {snapshot.snapshot_id}."
        ),
        findings=findings,
        duration_ms=int((time.monotonic() - started) * 1000),
        return_code=return_code,
        raw_report=raw,
        snapshot_provenance=snapshot.provenance(),
    )
