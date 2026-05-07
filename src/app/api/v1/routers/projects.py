"""Project / scan submission API.

Upload policy (V05.1.1):
    - Permitted ``files`` extensions: text source files only; non-source
      binary content is rejected by downstream processing.
    - Permitted ``archive_file`` extensions: see
      ``ALLOWED_ARCHIVE_EXTENSIONS`` in ``app.shared.lib.archive``.
    - Per-file size: enforced by downstream service / archive extractor.
    - Maximum number of files: 5000 per submission (router cap).
    - Maximum number of selected_files entries: 5000.
    - Maximum uncompressed archive size: ``MAX_UNCOMPRESSED_SIZE_BYTES``
      (100 MB) and ``MAX_FILES_IN_ARCHIVE`` (1000), both enforced by
      ``app.shared.lib.archive``.
    - Repository URLs: must be ``https://`` (or ``git+https://``) and the
      host must appear in the SSRF allowlist below; otherwise the router
      rejects with HTTP 400 (V01.3.6 / V05.3.2). See ``_validate_repo_url``.
    - Malicious / unsupported file detection: the router responds with
      HTTPException 400; archives with disallowed entries are rejected at
      extraction time.
"""

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    UploadFile,
    File,
    Form,
    Response,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.config.config import settings
from app.infrastructure.auth.core import (
    current_active_user,
    current_active_user_sse,
    current_superuser,
)
from app.config.logging_config import correlation_id_var
from app.core.services.scan import (
    ScanLifecycleService,
    ScanQueryService,
    ScanSubmissionService,
)
from app.api.v1.dependencies import (
    get_current_user_tenant_id,
    get_scan_lifecycle_service,
    get_scan_query_service,
    get_scan_submission_service,
    get_llm_config_repository,
    get_visible_user_ids,
    get_visible_user_ids_sse,
)
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.shared.lib.git import clone_repo_and_get_files
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename

router = APIRouter()
logger = logging.getLogger(__name__)


# V01.3.6 / V05.3.2: SSRF allowlist applied at the router boundary before any
# git-clone helper is invoked. Hosts here are the well-known public hosting
# services; site operators tightening this should override via configuration.
_REPO_URL_ALLOWED_HOSTS = frozenset(
    {
        "github.com",
        "www.github.com",
        "gitlab.com",
        "www.gitlab.com",
        "bitbucket.org",
        "www.bitbucket.org",
    }
)
_REPO_URL_ALLOWED_SCHEMES = frozenset({"https", "git+https"})


def _validate_repo_url(repo_url: str) -> None:
    """Reject repo URLs that fail the SSRF allowlist.

    Rules:
        - scheme must be https (or git+https)
        - no userinfo component (no embedded credentials)
        - host must be in the allowlist
        - reject IP literals, loopback, link-local, RFC1918 — covered by
          rejecting any non-allowlisted host (a strict allowlist is the
          surest way to block these).
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(repo_url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid repo_url.")
    if parsed.scheme not in _REPO_URL_ALLOWED_SCHEMES:
        raise HTTPException(
            status_code=400,
            detail="repo_url scheme not allowed; use https.",
        )
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=400,
            detail="repo_url must not include embedded credentials.",
        )
    host = (parsed.hostname or "").lower()
    if not host or host not in _REPO_URL_ALLOWED_HOSTS:
        raise HTTPException(
            status_code=400,
            detail="repo_url host is not on the allowlist.",
        )


@router.get("/projects", response_model=api_models.PaginatedProjectHistoryResponse)
async def get_all_projects(
    user: db_models.User = Depends(current_active_user),
    service: ScanQueryService = Depends(get_scan_query_service),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    tenant_id=Depends(get_current_user_tenant_id),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None, min_length=1, max_length=100),
):
    return await service.get_paginated_projects(
        user.id,
        skip,
        limit,
        search,
        visible_user_ids=visible_user_ids,
        tenant_id=tenant_id,
    )


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_. -]+$")


@router.post(
    "/projects",
    response_model=api_models.ProjectHistoryItem,
    status_code=status.HTTP_201_CREATED,
)
async def create_project(
    request: CreateProjectRequest,
    user: db_models.User = Depends(current_active_user),
    service: ScanQueryService = Depends(get_scan_query_service),
):
    """Creates a new empty project."""
    project = await service.repo.get_or_create_project(
        name=request.name, user_id=user.id
    )
    return api_models.ProjectHistoryItem(
        id=project.id,
        name=project.name,
        repository_url=project.repository_url,
        created_at=project.created_at,
        updated_at=project.updated_at,
        scans=[],
    )


@router.get("/projects/search", response_model=List[str])
async def search_projects_for_user(
    q: str = Query(..., min_length=1, max_length=100),
    user: db_models.User = Depends(current_active_user),
    service: ScanQueryService = Depends(get_scan_query_service),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    tenant_id=Depends(get_current_user_tenant_id),
):
    """Searches for projects by name visible to the caller (for autocomplete)."""
    return await service.search_projects(
        user_id=user.id,
        query=q,
        visible_user_ids=visible_user_ids,
        tenant_id=tenant_id,
    )


@router.get("/scans/history", response_model=api_models.PaginatedScanHistoryResponse)
async def get_user_scan_history(
    user: db_models.User = Depends(current_active_user),
    service: ScanQueryService = Depends(get_scan_query_service),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    tenant_id=Depends(get_current_user_tenant_id),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: Optional[str] = Query(None, min_length=1, max_length=100),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    status: Optional[str] = Query(None),
):
    """Retrieves a paginated list of all scans visible to the caller."""
    return await service.get_paginated_user_scans(
        user_id=user.id,
        skip=(page - 1) * page_size,
        limit=page_size,
        search=search,
        sort_order=sort_order,
        status=status,
        visible_user_ids=visible_user_ids,
        tenant_id=tenant_id,
    )


@router.post("/scans/preview-archive", response_model=dict)
async def preview_archive_files(
    archive_file: UploadFile = File(...),
    _user: db_models.User = Depends(current_active_user),
):
    if not archive_file.filename or not is_archive_filename(archive_file.filename):
        raise HTTPException(
            status_code=400, detail="Invalid or unsupported archive file provided."
        )
    # V05.3.2: reject filenames with path separators or NULs.
    if (
        "/" in archive_file.filename
        or "\\" in archive_file.filename
        or "\x00" in archive_file.filename
    ):
        raise HTTPException(status_code=400, detail="Invalid archive filename.")
    files_data = extract_archive_to_files(archive_file)
    return {"files": [f["path"] for f in files_data]}


@router.post("/scans/preview-git", response_model=dict)
async def preview_git_files(
    request: api_models.GitRepoPreviewRequest,
    _user: db_models.User = Depends(current_active_user),
):
    # V01.3.6 / V05.3.2: SSRF allowlist before any clone.
    _validate_repo_url(request.repo_url)
    files_data = clone_repo_and_get_files(request.repo_url)
    if not files_data:
        raise HTTPException(
            status_code=400,
            detail="Repository cloned, but no processable files were found.",
        )
    return {"files": [f["path"] for f in files_data]}


@router.post("/scans", response_model=api_models.ScanResponse)
async def create_scan(
    service: ScanSubmissionService = Depends(get_scan_submission_service),
    llm_repo: LLMConfigRepository = Depends(get_llm_config_repository),
    user: db_models.User = Depends(current_active_user),
    project_name: str = Form(
        ..., min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_. -]+$"
    ),
    scan_type: str = Form(..., pattern=r"^(AUDIT|SUGGEST|REMEDIATE)$"),
    reasoning_llm_config_id: Optional[uuid.UUID] = Form(None),
    frameworks: str = Form(
        ..., min_length=1, max_length=2048
    ),  # Received as a string, will be processed in service
    repo_url: Optional[str] = Form(None, max_length=2048, pattern=r"^https?://.+"),
    files: Optional[List[UploadFile]] = File(None),
    archive_file: Optional[UploadFile] = File(None),
    selected_files: Optional[str] = Form(None, max_length=200000),
):
    # V05.3.2: reject selected_files entries containing traversal/null/backslash.
    if selected_files and any(ch in selected_files for ch in ("..", "\x00", "\\")):
        raise HTTPException(
            status_code=400,
            detail="selected_files contains invalid characters or path traversal sequences.",
        )
    selected_files_list = (
        [p.strip() for p in selected_files.split(",") if p.strip()]
        if selected_files
        else None
    )
    # V02.2.1 / V02.3.2: cap selected_files entries.
    if selected_files_list is not None and len(selected_files_list) >= 5000:
        raise HTTPException(
            status_code=413,
            detail="Too many entries in selected_files (max 5000).",
        )
    # Reject any selected entries with absolute path or traversal segments.
    if selected_files_list:
        for p in selected_files_list:
            if p.startswith("/") or ".." in p.split("/"):
                raise HTTPException(
                    status_code=400,
                    detail="selected_files contains an invalid path entry.",
                )

    # V01.3.6 / V05.3.2: SSRF allowlist for repo_url before any clone.
    if repo_url:
        _validate_repo_url(repo_url)

    # V05.3.2: reject archive filenames with path separators or NULs.
    if archive_file and archive_file.filename:
        if (
            "/" in archive_file.filename
            or "\\" in archive_file.filename
            or "\x00" in archive_file.filename
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid archive filename.",
            )

    # V02.3.2 / V05.2.1: cap number of uploaded files at the router boundary.
    if files is not None and len(files) > 5000:
        raise HTTPException(
            status_code=413,
            detail="Too many files uploaded (max 5000).",
        )

    # Resolve a missing reasoning_llm_config_id to a fallback config.
    # Supports the fresh-setup case where the admin has just configured
    # one LLM — we use it without forcing the operator to specify it
    # again on every submit.
    if reasoning_llm_config_id is None:
        available = await llm_repo.get_all(skip=0, limit=1)
        if not available:
            raise HTTPException(
                status_code=400,
                detail=(
                    "No LLM configurations available. Ask an admin to add one "
                    "under Admin → LLM Configurations before submitting a scan."
                ),
            )
        reasoning_llm_config_id = available[0].id

    common_args = {
        "project_name": project_name,
        "user_id": user.id,
        "correlation_id": correlation_id_var.get(),
        "scan_type": scan_type,
        "reasoning_llm_config_id": reasoning_llm_config_id,
        "frameworks": [fw.strip() for fw in frameworks.split(",")],
        "selected_files": selected_files_list,
    }

    submission_methods_count = sum(
        1 for method in [files, repo_url, archive_file] if method
    )
    if submission_methods_count != 1:
        raise HTTPException(
            status_code=400,
            detail="Exactly one submission method (files, repo_url, or archive_file) must be provided.",
        )

    if files:
        scan = await service.create_scan_from_uploads(files=files, **common_args)
        submission_method = "files"
    elif repo_url:
        scan = await service.create_scan_from_git(repo_url=repo_url, **common_args)
        submission_method = "repo_url"
    elif archive_file:
        scan = await service.create_scan_from_archive(
            archive_file=archive_file, **common_args
        )
        submission_method = "archive"
    else:
        raise HTTPException(status_code=400, detail="No submission data provided.")

    logger.info(
        "scans.created",
        extra={
            "actor_id": user.id,
            "scan_id": str(scan.id),
            "project_id": str(scan.project_id),
            "scan_type": scan_type,
            "frameworks": [fw.strip() for fw in frameworks.split(",")],
            "submission_method": submission_method,
        },
    )

    return api_models.ScanResponse(
        scan_id=scan.id,
        project_id=scan.project_id,
        message="Scan initiated and queued for analysis.",
    )


@router.post(
    "/scans/{scan_id}/approve",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=dict,
)
async def approve_scan_analysis(
    scan_id: uuid.UUID,
    request: Optional[api_models.ApprovalRequest] = None,
    user: db_models.User = Depends(current_active_user),
    service: ScanLifecycleService = Depends(get_scan_lifecycle_service),
):
    """Resume a scan paused at a worker-graph interrupt.

    Two interrupt points exist (ADR-009): the prescan-approval gate
    (status `PENDING_PRESCAN_APPROVAL`) and the existing cost-approval
    gate (status `PENDING_COST_APPROVAL`). The body's ``kind`` field
    discriminates. Body is optional; missing body defaults to
    ``kind="cost_approval", approved=True`` for backward compat.
    """
    await service.approve_scan(scan_id, user, request)
    logger.info(
        "scans.approved",
        extra={
            "actor_id": user.id,
            "scan_id": str(scan_id),
            "kind": (
                getattr(request, "kind", "cost_approval")
                if request
                else "cost_approval"
            ),
            "approved": getattr(request, "approved", True) if request else True,
        },
    )
    return {"message": "Scan approved and queued for processing."}


@router.get(
    "/scans/{scan_id}/prescan-findings",
    response_model=api_models.PrescanReviewResponse,
)
async def get_prescan_review(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: ScanLifecycleService = Depends(get_scan_lifecycle_service),
):
    """Deterministic-scanner findings to render on the prescan-approval card.

    Only valid while the scan sits at ``PENDING_PRESCAN_APPROVAL`` (the
    gate) or has landed in one of the two prescan-terminal states
    (``BLOCKED_PRE_LLM`` / ``BLOCKED_USER_DECLINE``).
    """
    return await service.get_prescan_review(scan_id, user)


@router.post(
    "/scans/{scan_id}/cancel", status_code=status.HTTP_200_OK, response_model=dict
)
async def cancel_scan_analysis(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: ScanLifecycleService = Depends(get_scan_lifecycle_service),
):
    """Cancels a scan, typically one that is pending cost approval."""
    await service.cancel_scan(scan_id, user)
    logger.info(
        "scans.cancelled",
        extra={"actor_id": user.id, "scan_id": str(scan_id)},
    )
    return {"message": "Scan has been cancelled successfully."}


@router.post("/scans/{scan_id}/stream-token", response_model=dict)
async def issue_scan_stream_token(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: ScanQueryService = Depends(get_scan_query_service),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
):
    """Mint a short-TTL JWT for the SSE stream of this scan.

    EventSource cannot send Authorization headers, so the frontend
    POSTs here (with the regular Bearer header), gets back a token,
    and appends it to the stream URL as `?access_token=…`. The token
    is audience-tagged "sse:scan-stream", scan-id-bound, and 60s-TTL —
    it cannot be substituted for a regular access token at any other
    endpoint, and cannot be replayed against a different scan.

    Authorization mirrors the SSE endpoint itself (owner / admin /
    peer per H.2). Re-checked at the stream URL even if a stale token
    survives, so this is defence-in-depth, not the only gate.
    """
    from app.infrastructure.auth.sse_token import mint_scan_stream_token

    scan = await service.get_scan_status(scan_id, user)
    is_owner = scan.user_id == user.id
    is_admin = user.is_superuser
    is_peer = visible_user_ids is not None and scan.user_id in visible_user_ids
    if not (is_owner or is_admin or is_peer):
        logger.warning(
            "scans.stream_token.access_denied",
            extra={"actor_id": user.id, "scan_id": str(scan_id)},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to stream this scan.",
        )

    token, expires_in = mint_scan_stream_token(user.id, scan_id)
    return {"access_token": token, "expires_in": expires_in}


@router.get("/scans/{scan_id}/stream")
async def stream_scan_progress(
    scan_id: uuid.UUID,
    request: Request,
    user: db_models.User = Depends(current_active_user_sse),
    service: ScanQueryService = Depends(get_scan_query_service),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids_sse),
):
    """Server-Sent Events stream of a scan's progress.

    Emits a `scan_state` event for status transitions, a `scan_event` for
    each new pipeline stage (ScanEvent row), and a terminal `done` event
    when the scan reaches a final state. The client reconnects via
    EventSource's native retry.

    Implementation: polls the DB at 1-second intervals — simpler than
    wiring LangGraph event streaming and sufficient for the per-stage
    granularity the UI wants. Can be upgraded later if we need per-file
    finding deltas mid-scan.

    Security note (V14.1.2 / V14.2.1):
        EventSource cannot set custom headers; this endpoint accepts an
        access_token query parameter as a documented exception to V14.2.1.
        The token is intended to be single-use, scan-id-bound, with a 60s
        TTL, and is intentionally not echoed in any log line.
    """
    # Authz: reuse the existing service check.
    scan = await service.get_scan_status(scan_id, user)
    if scan.user_id != user.id and not user.is_superuser:
        logger.warning(
            "scans.stream.access_denied",
            extra={"actor_id": user.id, "scan_id": str(scan_id)},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to stream this scan.",
        )

    terminal_statuses = {
        "COMPLETED",
        "REMEDIATION_COMPLETED",
        "FAILED",
        "CANCELLED",
        "EXPIRED",
        # ADR-009 terminal states from the prescan-approval gate.
        "BLOCKED_PRE_LLM",
        "BLOCKED_USER_DECLINE",
    }
    # §3.10a: prefer LISTEN/NOTIFY-driven re-reads over a per-client
    # 1 Hz Postgres poll. The bus dispatches a notification whenever
    # `update_status` or `create_scan_event` commits in any process;
    # this handler subscribes, awaits the next signal, then re-reads
    # the scan to surface the change. Falls back to a slower poll
    # (`fallback_interval_seconds`) when the bus is unavailable or the
    # `queue.get()` times out — that wakeup acts as a heartbeat that
    # also catches any notification we missed (e.g. dispatcher dropped
    # one due to a backed-up subscriber queue).
    fallback_interval_seconds = 5.0
    # Bound on the stream's lifetime as a safety net; the scan-workflow
    # timeout (default 2h) dominates in practice.
    max_stream_seconds = settings.SCAN_WORKFLOW_TIMEOUT_SECONDS

    from app.infrastructure.messaging.scan_progress_notifier import (
        get_scan_progress_bus,
    )

    bus = get_scan_progress_bus()
    queue: Optional["asyncio.Queue[str]"] = None
    if bus is not None:
        try:
            queue = await bus.subscribe(
                str(scan_id),
                owner_user_id=user.id,
                visible_user_ids=visible_user_ids,
            )
        except PermissionError:
            raise
        except Exception as e:
            logger.warning(
                "SSE: bus subscribe failed for scan %s: %s; falling back to polling.",
                scan_id,
                e,
            )
            queue = None

    # Resume position for reconnects. EventSource's built-in retry
    # sets the `Last-Event-ID` header to the last `id:` line it saw,
    # so honoring it suppresses the duplicate-event flood we'd
    # otherwise emit on every reconnect (the live event log was
    # rendering QUEUED · COMPLETED 3× because we kept replaying from
    # id=0). Our manual reconnect path mints a fresh JWT on a brand-
    # new EventSource, which doesn't replay the header — it passes
    # the same value as `?last_event_id=…` instead.
    resume_event_id = 0
    header_resume = request.headers.get("last-event-id")
    if header_resume:
        try:
            resume_event_id = max(resume_event_id, int(header_resume))
        except ValueError:
            pass
    qp_resume = request.query_params.get("last_event_id")
    if qp_resume:
        try:
            resume_event_id = max(resume_event_id, int(qp_resume))
        except ValueError:
            pass

    async def event_generator():
        import asyncio as _asyncio
        import json as _json
        import time as _time

        start = _time.monotonic()
        last_event_id = resume_event_id
        last_status: Optional[str] = None

        try:
            while True:
                if await request.is_disconnected():
                    logger.info(
                        "SSE: client disconnected, ending stream.",
                        extra={"scan_id": str(scan_id), "user_id": user.id},
                    )
                    return
                if _time.monotonic() - start > max_stream_seconds:
                    yield (
                        f"event: timeout\n"
                        f"data: {_json.dumps({'scan_id': str(scan_id)})}\n\n"
                    )
                    return

                scan = await service.get_scan_status(scan_id, user)

                # Emit on status change (including the first tick).
                if scan.status != last_status:
                    last_status = scan.status
                    payload: Dict[str, Any] = {
                        "scan_id": str(scan_id),
                        "status": scan.status,
                    }
                    # Surface `cost_details` on the cost-approval flip so
                    # the frontend can render the estimate live without
                    # a manual refresh. Only sent at the moment we cross
                    # into PENDING_COST_APPROVAL — the JSONB blob is
                    # otherwise an internal artifact (V15.3.1) and
                    # there's no UI reason to keep streaming it.
                    if scan.status == "PENDING_COST_APPROVAL" and scan.cost_details:
                        cd = scan.cost_details
                        payload["cost_details"] = {
                            "total_estimated_cost": cd.get("total_estimated_cost"),
                            "total_input_tokens": cd.get("total_input_tokens"),
                            "predicted_output_tokens": cd.get(
                                "predicted_output_tokens"
                            ),
                        }
                    yield (f"event: scan_state\n" f"data: {_json.dumps(payload)}\n\n")

                # Emit any ScanEvents with id > last_event_id.
                events = sorted(
                    (e for e in (scan.events or []) if e.id > last_event_id),
                    key=lambda e: e.id,
                )
                for e in events:
                    last_event_id = e.id
                    payload = {
                        "scan_id": str(scan_id),
                        "event_id": e.id,
                        "stage_name": e.stage_name,
                        "status": e.status,
                        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                        # §3.10b: per-event payload (e.g. file_path +
                        # findings_count for `FILE_ANALYZED`). None for
                        # legacy stage events.
                        "details": e.details,
                    }
                    yield (
                        f"event: scan_event\n"
                        f"id: {e.id}\n"
                        f"data: {_json.dumps(payload)}\n\n"
                    )

                if scan.status in terminal_statuses:
                    yield (
                        f"event: done\n"
                        f"data: {_json.dumps({'scan_id': str(scan_id), 'status': scan.status})}\n\n"
                    )
                    return

                if queue is not None:
                    # Bus path: wait for a NOTIFY (status / event change).
                    # Fallback to the heartbeat interval if the bus goes
                    # quiet for too long — guards against lost notifications.
                    try:
                        await _asyncio.wait_for(
                            queue.get(), timeout=fallback_interval_seconds
                        )
                    except _asyncio.TimeoutError:
                        # Heartbeat tick — re-read on next loop iteration.
                        pass
                else:
                    # Bus unavailable — degrade to legacy 1 Hz poll.
                    await _asyncio.sleep(1.0)
        finally:
            # Always unsubscribe so the bus's per-scan subscriber set
            # doesn't leak entries on client-disconnect / timeout.
            if bus is not None and queue is not None:
                try:
                    await bus.unsubscribe(str(scan_id), queue)
                except Exception:
                    pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream; charset=utf-8",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering for SSE
            "Connection": "keep-alive",
        },
    )


class SelectiveRemediationRequest(BaseModel):
    finding_ids: List[int]


@router.post(
    "/scans/{scan_id}/apply-fixes",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=dict,
)
async def apply_fixes(
    scan_id: uuid.UUID,
    request: SelectiveRemediationRequest,
    user: db_models.User = Depends(current_active_user),
    service: ScanLifecycleService = Depends(get_scan_lifecycle_service),
):
    """Triggers the application of selected fixes for a scan."""
    await service.apply_selective_fixes(scan_id, request.finding_ids, user)
    logger.info(
        "scans.fixes_applied",
        extra={
            "actor_id": user.id,
            "scan_id": str(scan_id),
            "finding_count": len(request.finding_ids),
        },
    )
    return {
        "message": "Fix application process initiated. The scan status will be updated upon completion."
    }


@router.get(
    "/scans/{scan_id}/result", response_model=api_models.AnalysisResultDetailResponse
)
async def get_scan_result_details(
    scan_id: uuid.UUID,
    include_source: bool = Query(False),
    user: db_models.User = Depends(current_active_user),
    service: ScanQueryService = Depends(get_scan_query_service),
):
    """Retrieves the full, detailed result of a completed scan."""
    result = await service.get_scan_result(scan_id, user, include_source=include_source)

    return result


@router.get(
    "/projects/{project_id}/scans",
    response_model=api_models.PaginatedScanHistoryResponse,
)
async def get_scan_history_for_project(
    project_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: ScanQueryService = Depends(get_scan_query_service),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    tenant_id=Depends(get_current_user_tenant_id),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    return await service.get_paginated_scans_for_project(
        project_id,
        user,
        skip,
        limit,
        visible_user_ids=visible_user_ids,
        tenant_id=tenant_id,
    )


@router.get(
    "/scans/{scan_id}/llm-interactions",
    response_model=List[api_models.LLMInteractionResponse],
)
async def get_llm_interactions_for_scan(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: ScanQueryService = Depends(get_scan_query_service),
):
    """Retrieves all LLM interactions associated with a specific scan."""
    interactions_db = await service.get_llm_interactions_for_scan(scan_id, user)
    return [
        api_models.LLMInteractionResponse.from_orm(inter) for inter in interactions_db
    ]


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_superuser),
    service: ScanQueryService = Depends(get_scan_query_service),
):
    """Deletes a single scan (superuser only)."""
    await service.delete_scan_by_id(scan_id, user)
    logger.info(
        "scans.delete",
        extra={"actor_id": user.id, "scan_id": str(scan_id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: uuid.UUID,
    user: db_models.User = Depends(current_superuser),
    service: ScanQueryService = Depends(get_scan_query_service),
):
    """Delets a project and all its scans (superuser only)."""
    await service.delete_project_by_id(project_id, user)
    logger.info(
        "projects.delete",
        extra={"actor_id": user.id, "project_id": str(project_id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
