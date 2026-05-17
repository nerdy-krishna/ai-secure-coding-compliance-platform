"""Scan-submission service: creates Scan + Snapshot + Outbox rows
and publishes the kickoff message to RabbitMQ.

Split out of `core/services/scan_service.py` (2026-04-26). Method
bodies are verbatim copies — no logic change.

Submission limits
-----------------
- ``MAX_FILES_PER_SCAN``  – maximum number of files accepted per scan.
- ``MAX_TOTAL_BYTES``     – maximum aggregate uncompressed content bytes.
- ``MAX_FILE_BYTES``      – maximum per-file size in bytes.
- ``MAX_PATH_LEN``        – maximum length of an individual file path.

Allowed values for ``scan_type`` and ``frameworks`` are enforced at the
service layer; see ``_VALID_SCAN_TYPES`` and ``_VALID_FRAMEWORKS``.

Uploaded filenames are validated for path-traversal characters before
being stored.  Git ``repo_url`` values are restricted to HTTPS URLs on
known public hosting domains.

Files whose first bytes match common executable magic numbers are
rejected immediately after reading to prevent binary blobs being stored
as source code.

On any constraint violation the service raises ``HTTPException(400)``
(or 413 for oversized content).  Internal errors during the DB write
chain are logged with full context before re-raising.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from fastapi import HTTPException, UploadFile, status
from sqlalchemy import select

from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.messaging.publisher import publish_message
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename
from app.shared.lib.files import get_language_from_filename
from app.shared.lib.framework_validation import validate_framework_selection
from app.shared.lib.git import clone_repo_and_get_files

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Submission limits (V02.1.3 / V05.2.1)
# ---------------------------------------------------------------------------
MAX_FILES_PER_SCAN: int = 5_000
MAX_TOTAL_BYTES: int = 200 * 1024 * 1024  # 200 MB aggregate
MAX_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB per file
MAX_PATH_LEN: int = 1_024

# ---------------------------------------------------------------------------
# Input-validation allow-lists (V02.2.1)
# ---------------------------------------------------------------------------
_VALID_SCAN_TYPES: frozenset[str] = frozenset({"AUDIT", "SUGGEST", "REMEDIATE"})
# Framework names are validated against the live `frameworks` table —
# see `validate_framework_selection`.

# repo_url must be https:// on a known public code-hosting domain (V05.3.2)
_REPO_URL_RE = re.compile(
    r"^https://(github\.com|gitlab\.com|bitbucket\.org)" r"/[A-Za-z0-9._/-]+(?:\.git)?$"
)

# Magic bytes for common executable formats (V05.2.2)
_EXECUTABLE_MAGIC: tuple[bytes, ...] = (
    b"MZ",  # PE/DOS
    b"\x7fELF",  # ELF
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary / Java class
    b"#!",  # shebang (shell scripts etc.)
)


def _redact_repo_url(url: str) -> str:
    """Return *url* with any userinfo (credentials) stripped (V16.2.5)."""
    try:
        parts = urlsplit(url)
        # Rebuild netloc without userinfo
        host_only = parts.hostname or ""
        if parts.port:
            host_only = f"{host_only}:{parts.port}"
        clean = parts._replace(netloc=host_only)
        return urlunsplit(clean)
    except Exception:
        return "<redacted>"


class ScanSubmissionService:
    """New-scan creation + initial outbox-publish path.

    `__init__` constructs the outbox repo from the SAME session as the
    scan repo so `_process_and_launch_scan` can write Scan +
    CodeSnapshot + ScanOutbox atomically (G-split-2 from the threat
    model).
    """

    def __init__(self, repo: ScanRepository):
        self.repo = repo
        self.outbox = ScanOutboxRepository(repo.db)

    async def _resolve_user_tenant_id(self, user_id: int) -> Optional[uuid.UUID]:
        """Look up the submitter's tenant for stamping on Project + Scan.

        Returns ``None`` when the user has no tenant (orphan / pre-Chunk-7);
        the repo helpers treat ``None`` as "leave whatever's there"."""
        result = await self.repo.db.execute(
            select(db_models.User.tenant_id).where(db_models.User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def _process_and_launch_scan(
        self,
        project_name: str,
        user_id: int,
        files_data: List[Dict[str, Any]],
        scan_type: str,
        correlation_id: str,
        reasoning_llm_config_id: uuid.UUID,
        frameworks: List[str],
        repo_url: Optional[str] = None,
        selected_files: Optional[List[str]] = None,
    ) -> db_models.Scan:
        """
        A private helper to process submission data, create all necessary DB records,
        and publish a message to kick off the workflow.
        """
        # --- Input validation (V02.2.1) --------------------------------------
        if scan_type not in _VALID_SCAN_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scan_type '{scan_type}'. Must be one of {sorted(_VALID_SCAN_TYPES)}.",
            )
        await validate_framework_selection(self.repo.db, frameworks)
        if not project_name or len(project_name) > 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="project_name must be between 1 and 200 characters.",
            )

        if selected_files:
            # Filter the files_data to only include user-selected files
            selected_files_set = set(selected_files)
            original_count = len(files_data)
            # Detect unknown selections before filtering (V02.2.3)
            available_paths = {f["path"] for f in files_data}
            unknown = selected_files_set - available_paths
            if unknown:
                sample = sorted(unknown)[:5]
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unknown selected files (showing up to 5): {sample}",
                )
            files_data = [f for f in files_data if f["path"] in selected_files_set]
            logger.info(
                "scan-submission: filtered by user selection",
                extra={
                    "original_count": original_count,
                    "selected_count": len(files_data),
                },
            )

        # --- Cross-field reasonableness check (V02.2.3) ----------------------
        if not files_data:
            if selected_files:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "None of the selected files matched the uploaded set; "
                        "check your selection."
                    ),
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No files were provided for analysis.",
            )

        # --- Aggregate size / count caps (V02.1.3) ---------------------------
        if len(files_data) > MAX_FILES_PER_SCAN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Submission exceeds the maximum of {MAX_FILES_PER_SCAN} files.",
            )
        total_bytes = sum(len(f["content"].encode()) for f in files_data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Submission exceeds the maximum total size of "
                    f"{MAX_TOTAL_BYTES // (1024 * 1024)} MB."
                ),
            )

        # --- DB write chain (V16.3.4: wrap for structured error logging) -----
        # Resolve the submitter's tenant up-front so both Project and Scan
        # land in the same tenant. None is acceptable (orphan / pre-Chunk-7)
        # — repo helpers ignore it and the row keeps its existing tenant_id
        # via ON CONFLICT DO NOTHING.
        tenant_id = await self._resolve_user_tenant_id(user_id)
        try:
            # 1. Get or create the project
            project = await self.repo.get_or_create_project(
                name=project_name,
                user_id=user_id,
                repo_url=repo_url,
                tenant_id=tenant_id,
            )

            # 2. Get or create deduplicated source code files
            file_hashes = await self.repo.get_or_create_source_files(files_data)

            # 3. Create the file map for the snapshot {path: hash}
            file_map = {
                file_data["path"]: file_hash
                for file_data, file_hash in zip(files_data, file_hashes)
            }

            # 4. Create the Scan record
            scan = await self.repo.create_scan(
                project_id=project.id,
                user_id=user_id,
                scan_type=scan_type,
                reasoning_llm_config_id=reasoning_llm_config_id,
                frameworks=frameworks,
                tenant_id=tenant_id,
            )

            # 5. Create the Code Snapshot linked to the scan
            await self.repo.create_code_snapshot(
                scan_id=scan.id, file_map=file_map, snapshot_type="ORIGINAL_SUBMISSION"
            )

            # 6. Add "QUEUED" event to the timeline
            await self.repo.create_scan_event(
                scan_id=scan.id, stage_name="QUEUED", status="COMPLETED"
            )

            # 7. Persist an outbox row FIRST, so the sweep task can retry the
            # publish later if RabbitMQ is down right now.
            payload = {"scan_id": str(scan.id)}
            outbox_row = await self.outbox.enqueue(
                scan_id=scan.id,
                queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
                payload=payload,
            )

            # 8. Attempt the publish inline. Best-effort: on failure, the outbox
            # sweeper will re-publish.
            published = await publish_message(
                queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
                message_body=payload,
                correlation_id=correlation_id,
            )
            if published:
                await self.outbox.mark_published(outbox_row.id)
                logger.info(
                    "scan-submission: published",
                    extra={"correlation_id": correlation_id, "scan_id": str(scan.id)},
                )
            else:
                await self.outbox.record_failed_attempt(outbox_row.id)
                logger.warning(
                    "scan-submission: publish failed; outbox sweeper will retry",
                    extra={"correlation_id": correlation_id, "scan_id": str(scan.id)},
                )
        except HTTPException:
            raise
        except Exception:
            logger.error(
                "scan-submission: launch chain failed",
                extra={
                    "correlation_id": correlation_id,
                    "user_id": user_id,
                    "file_count": len(files_data),
                },
                exc_info=True,
            )
            raise

        return scan

    async def create_scan_from_uploads(
        self, *, files: List[UploadFile], **kwargs
    ) -> db_models.Scan:
        """Handles submission from direct file uploads."""
        logger.info(
            "Creating scan from file uploads.", extra={"file_count": len(files)}
        )
        files_data = []
        aggregate_bytes = 0
        for file in files:
            if not file.filename:
                continue

            # --- Filename path-traversal guard (V05.3.2 / V02.2.1) ----------
            fname = file.filename
            if (
                ".." in fname
                or "\x00" in fname
                or fname.startswith("/")
                or fname.startswith("\\")
                or len(fname) > MAX_PATH_LEN
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid filename: {fname!r}",
                )

            if is_archive_filename(fname):
                raise HTTPException(
                    status_code=400,
                    detail=f"Archive file '{fname}' submitted incorrectly. Use the 'Upload Archive' option.",
                )

            # --- Streaming read with per-file size cap (V05.2.1) -------------
            chunks: list[bytes] = []
            file_total = 0
            _chunk_size = 65_536  # 64 KiB
            while True:
                chunk = await file.read(_chunk_size)
                if not chunk:
                    break
                file_total += len(chunk)
                if file_total > MAX_FILE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=(
                            f"File '{fname}' exceeds the maximum allowed size of "
                            f"{MAX_FILE_BYTES // (1024 * 1024)} MB."
                        ),
                    )
                chunks.append(chunk)
            content_bytes = b"".join(chunks)

            # Aggregate cap (V05.2.1)
            aggregate_bytes += len(content_bytes)
            if aggregate_bytes > MAX_TOTAL_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=(
                        f"Total upload size exceeds the maximum of "
                        f"{MAX_TOTAL_BYTES // (1024 * 1024)} MB."
                    ),
                )

            # --- Executable magic-byte rejection (V05.2.2) -------------------
            header = content_bytes[:8]
            for magic in _EXECUTABLE_MAGIC:
                if header.startswith(magic):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"File {fname!r} appears to be an executable and cannot be submitted.",
                    )

            try:
                content_str = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                content_str = content_bytes.decode("latin-1", errors="ignore")

            files_data.append(
                {
                    "path": fname,
                    "content": content_str.replace("\x00", ""),
                    "language": get_language_from_filename(fname) or "unknown",
                }
            )

        return await self._process_and_launch_scan(files_data=files_data, **kwargs)

    async def create_scan_from_git(self, *, repo_url: str, **kwargs) -> db_models.Scan:
        """Handles submission from a Git repository."""
        # --- Validate repo_url: HTTPS only on known public hosts (V05.3.2 / V02.2.1) ---
        parsed = urlsplit(repo_url)
        if parsed.username or parsed.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Credentials must not be embedded in the repository URL.",
            )
        if not _REPO_URL_RE.match(repo_url):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "repo_url must be an HTTPS URL on github.com, gitlab.com, or "
                    "bitbucket.org, e.g. https://github.com/owner/repo"
                ),
            )
        logger.info(
            "scan-submission: from git",
            extra={"repo_url": _redact_repo_url(repo_url)},
        )
        files_data = clone_repo_and_get_files(repo_url)
        return await self._process_and_launch_scan(
            files_data=files_data, repo_url=repo_url, **kwargs
        )

    async def create_scan_from_archive(
        self, *, archive_file: UploadFile, **kwargs
    ) -> db_models.Scan:
        """Handles submission from an archive file."""
        logger.info(
            "scan-submission: from archive",
            extra={"archive_filename": archive_file.filename},
        )
        files_data = extract_archive_to_files(archive_file)
        return await self._process_and_launch_scan(files_data=files_data, **kwargs)
