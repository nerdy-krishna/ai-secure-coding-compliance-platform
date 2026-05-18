# src/app/api/mcp/server.py
"""FastMCP server exposing SCCAP's scanner + advisor surfaces as
Model Context Protocol tools, mounted at /mcp on the main FastAPI app.

Agentic clients (Claude Code, Cursor, etc.) authenticate with the
same JWT they'd use for the REST API: the `Authorization: Bearer
<token>` header is verified against the fastapi-users strategy via
`_SCCAPJWTVerifier`. Tool handlers resolve the authenticated user
out of the MCP request context so admin / ownership checks mirror
what `/api/v1/*` routes already enforce.

Tool surface (v1):
    - sccap_submit_scan
    - sccap_get_scan_status
    - sccap_get_scan_result
    - sccap_approve_scan
    - sccap_apply_fixes
    - sccap_ask_advisor
"""

from __future__ import annotations

import logging
import posixpath
import uuid
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_users.db import SQLAlchemyUserDatabase

from app.config.config import settings
from app.core.services.chat_service import ChatService
from app.core.services.scan import (
    ScanLifecycleService,
    ScanQueryService,
    ScanSubmissionService,
)
from app.infrastructure.auth.backend import get_custom_cookie_jwt_strategy
from app.infrastructure.auth.manager import UserManager
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.repositories.chat_repo import ChatRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository

# Submission size limits — enforced at the MCP boundary (V02.2.1, V05.1.1, V05.2.1).
MAX_FILES_PER_SUBMISSION = 1_000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 500_000_000

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token verification — reuse fastapi-users' JWT strategy so MCP tokens and
# REST tokens are interchangeable.
# ---------------------------------------------------------------------------


class _SCCAPJWTVerifier(TokenVerifier):
    """Validates a SCCAP access token via fastapi-users' JWT strategy.

    Caches the user manager factory but resolves the user per-request so
    that deactivated accounts lose MCP access immediately.
    """

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        strategy = get_custom_cookie_jwt_strategy()
        try:
            async with AsyncSessionLocal() as session:
                user_db = SQLAlchemyUserDatabase(session, db_models.User)
                manager = UserManager(user_db)
                user = await strategy.read_token(token, manager)
        except Exception as e:  # pragma: no cover — auth errors are expected
            logger.warning("mcp.auth.failed", extra={"error": str(e)})
            return None
        if user is None or not user.is_active:
            logger.warning(
                "mcp.auth.rejected_inactive",
                extra={"user_id": str(getattr(user, "id", None))},
            )
            return None

        scopes = ["admin"] if user.is_superuser else ["user"]
        logger.info(
            "mcp.auth.success",
            extra={"user_id": str(user.id), "is_superuser": user.is_superuser},
        )
        return AccessToken(
            token=token,
            client_id=str(user.id),
            scopes=scopes,
            expires_at=None,
            claims={
                "sub": str(user.id),
                "email": user.email,
                "is_superuser": user.is_superuser,
            },
        )


# ---------------------------------------------------------------------------
# Tool I/O schemas — Pydantic so FastMCP advertises a strict schema to
# callers and rejects malformed requests before our services run.
# ---------------------------------------------------------------------------


class SubmitScanFile(BaseModel):
    path: str = Field(
        description="Relative path to the file.",
        min_length=1,
        max_length=1024,
    )
    content: str = Field(
        description="Full file contents as a string.",
        max_length=MAX_FILE_BYTES,
    )


class SubmitScanInput(BaseModel):
    project_name: str = Field(min_length=1, max_length=200)
    scan_type: str = Field(
        description="AUDIT (find-only), SUGGEST (find + propose fixes), or REMEDIATE "
        "(find + apply fixes to a snapshot).",
        pattern="^(AUDIT|SUGGEST|REMEDIATE)$",
    )
    frameworks: List[str] = Field(
        description=(
            "Framework names the scan should apply. Must match names returned "
            "from the /compliance/stats endpoint (asvs, proactive_controls, "
            "cheatsheets, or custom ones)."
        ),
        min_length=1,
        max_length=20,
    )
    llm_config_id: str = Field(
        description="UUID of the LLM configuration used for the scan's reasoning calls.",
        min_length=1,
        max_length=64,
    )
    secondary_reasoning_llm_config_id: Optional[str] = Field(
        default=None,
        description=(
            "Optional UUID of a SECOND reasoning LLM (PRD #91). When set, "
            "every analysis agent runs on both this config and llm_config_id, "
            "and their findings are unioned — what one model misses the other "
            "may catch. Confined to the analysis stage. Defaults to null "
            "(single-LLM analysis)."
        ),
        max_length=64,
    )
    temperature_analysis_secondary: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Optional analysis temperature for the SECOND reasoning LLM "
            "(PRD #91) — lets you run the same model in both slots at two "
            "temperatures. Ignored unless secondary_reasoning_llm_config_id "
            "is set. Defaults to the standard 0.2."
        ),
    )
    files: Optional[List[SubmitScanFile]] = Field(
        default=None,
        description=(
            "Inline file contents. Mutually exclusive with repo_url. "
            f"Maximum {MAX_FILES_PER_SUBMISSION} files; each file up to "
            f"{MAX_FILE_BYTES // 1_000_000} MB; aggregate up to "
            f"{MAX_TOTAL_BYTES // 1_000_000} MB."
        ),
        max_length=MAX_FILES_PER_SUBMISSION,
    )
    repo_url: Optional[str] = Field(
        default=None,
        pattern=r"^https://",
        description="Public git HTTPS URL (https:// only). Mutually exclusive with files.",
        max_length=2048,
    )
    cross_file_validation: bool = Field(
        default=False,
        description=(
            "Opt in to cross-file finding validation (PRD #75). When true, "
            "each eligible finding is re-judged against the code that calls "
            "and feeds it across other files. Improves accuracy at the cost "
            "of one extra LLM call per eligible finding. Defaults to false."
        ),
    )
    disable_temperature: bool = Field(
        default=False,
        description=(
            "Opt in to disabling SCCAP's temperature setting (PRD #91). When "
            "true, no temperature is sent on any LLM call in the scan and each "
            "model runs at its own provider default instead of SCCAP's 0.2. "
            "Defaults to false."
        ),
    )


class AskAdvisorInput(BaseModel):
    question: str = Field(min_length=1, max_length=8000)
    frameworks: Optional[List[str]] = Field(default=None, max_length=20)
    llm_config_id: Optional[str] = Field(
        default=None,
        description="Override the LLM config. Defaults to the first configured.",
        max_length=64,
    )


# ---------------------------------------------------------------------------
# Helpers for resolving the authenticated user inside tool handlers.
# ---------------------------------------------------------------------------


async def _current_user(session: AsyncSession) -> db_models.User:
    token = get_access_token()
    if token is None:
        logger.warning(
            "mcp.authz.denied",
            extra={"tool": "_current_user", "user_id": None, "resource_id": None},
        )
        raise PermissionError("No authenticated user available in MCP request context.")
    user_id = int(token.client_id)
    user = await session.get(db_models.User, user_id)
    if user is None or not user.is_active:
        logger.warning(
            "mcp.authz.denied",
            extra={
                "tool": "_current_user",
                "user_id": token.client_id,
                "resource_id": None,
            },
        )
        raise PermissionError("Authenticated user not found or inactive.")
    return user


def _build_submission_service(repo: ScanRepository) -> ScanSubmissionService:
    return ScanSubmissionService(repo)


def _build_lifecycle_service(repo: ScanRepository) -> ScanLifecycleService:
    return ScanLifecycleService(repo)


def _build_query_service(repo: ScanRepository) -> ScanQueryService:
    return ScanQueryService(repo)


def _build_chat_service(session: AsyncSession) -> ChatService:
    return ChatService(chat_repo=ChatRepository(session))


def _safe_relpath(p: str) -> str:
    """Sanitize a caller-supplied file path against path traversal (V05.3.2).

    Raises ValueError for any path that is absolute, contains NUL bytes,
    uses backslash-rooted UNC paths, uses a Windows drive letter, or resolves
    to a component that escapes the submission root via ``..`` sequences.
    Returns the POSIX-normalized relative path on success.
    """
    if not p or "\x00" in p:
        raise ValueError("invalid path: empty or contains NUL byte")
    # Reject absolute POSIX paths, UNC paths, and Windows drive letters.
    unix_p = p.replace("\\", "/")
    if unix_p.startswith("/") or unix_p.startswith("//"):
        raise ValueError(f"absolute path forbidden: {p!r}")
    if len(unix_p) > 1 and unix_p[1] == ":":
        raise ValueError(f"Windows drive path forbidden: {p!r}")
    norm = posixpath.normpath(unix_p)
    # normpath("") → "." which is safe; reject traversal escapes.
    if norm.startswith("..") or ("/../" in ("/" + norm + "/")):
        raise ValueError(f"path traversal forbidden: {p!r}")
    return norm


# ---------------------------------------------------------------------------
# The FastMCP server. Tools are declared module-level so the singleton is
# easy to import from main.py.
# ---------------------------------------------------------------------------


mcp = FastMCP(
    name="SCCAP",
    auth=_SCCAPJWTVerifier(),
    instructions=(
        "Tools to drive SCCAP (Secure Coding & Compliance Automation Platform): "
        "submit scans, check status, fetch results, approve cost-estimated scans, "
        "apply AI-suggested fixes, and ask the security advisor one-shot questions. "
        "All tools require a SCCAP JWT bearer token."
    ),
)


@mcp.tool
async def sccap_submit_scan(payload: SubmitScanInput) -> Dict[str, Any]:
    """Submit a new scan.

    Provide either ``files`` (inline source) or ``repo_url`` (public HTTPS git
    URL), not both.  Returns ``{scan_id, status}`` — poll
    ``sccap_get_scan_status`` until ``PENDING_COST_APPROVAL``, then call
    ``sccap_approve_scan`` to release the full analysis.

    Limits: up to {MAX_FILES_PER_SUBMISSION} files, {MAX_FILE_BYTES // 1_000_000} MB
    per file, {MAX_TOTAL_BYTES // 1_000_000} MB aggregate.  Paths must be
    relative and free of traversal sequences.  File contents must not contain
    NUL bytes.
    """
    try:
        if bool(payload.files) == bool(payload.repo_url):
            raise ValueError("Provide exactly one of `files` or `repo_url`.")

        async with AsyncSessionLocal() as session:
            user = await _current_user(session)
            logger.info(
                "mcp.tool.invoke",
                extra={
                    "tool": "sccap_submit_scan",
                    "user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "scan_id": None,
                },
            )
            scan_service = _build_submission_service(ScanRepository(session))

            llm_cfg_id = uuid.UUID(payload.llm_config_id)
            common_kwargs: Dict[str, Any] = dict(
                project_name=payload.project_name,
                user_id=user.id,
                scan_type=payload.scan_type,
                correlation_id=str(uuid.uuid4()),
                reasoning_llm_config_id=llm_cfg_id,
                frameworks=payload.frameworks,
                cross_file_validation=payload.cross_file_validation,
                disable_temperature=payload.disable_temperature,
                secondary_reasoning_llm_config_id=(
                    uuid.UUID(payload.secondary_reasoning_llm_config_id)
                    if payload.secondary_reasoning_llm_config_id
                    else None
                ),
                stage_temperatures=(
                    {"analysis_secondary": payload.temperature_analysis_secondary}
                    if payload.temperature_analysis_secondary is not None
                    else None
                ),
            )

            if payload.files:
                # V05.2.1 — file count / aggregate size guard.
                if len(payload.files) > MAX_FILES_PER_SUBMISSION:
                    raise ValueError(
                        f"Too many files (max {MAX_FILES_PER_SUBMISSION})."
                    )
                total_bytes = 0
                for f in payload.files:
                    encoded_len = len(f.content.encode("utf-8"))
                    if encoded_len > MAX_FILE_BYTES:
                        raise ValueError(
                            f"File {f.path!r} exceeds per-file size limit "
                            f"({MAX_FILE_BYTES // 1_000_000} MB)."
                        )
                    total_bytes += encoded_len
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ValueError("Aggregate submission size exceeds limit.")

                # Bypass the FastAPI UploadFile shape by calling the private
                # launcher directly with pre-decoded file dicts.
                from app.shared.lib.files import get_language_from_filename

                files_data = []
                for f in payload.files:
                    # V05.3.2 — sanitize caller-supplied paths.
                    safe_path = _safe_relpath(f.path)
                    # V05.2.2 — reject binary content masquerading as source.
                    if "\x00" in f.content:
                        raise ValueError(
                            f"File {f.path!r} contains NUL bytes; binary content "
                            "is not accepted."
                        )
                    files_data.append(
                        {
                            "path": safe_path,
                            "content": f.content,
                            "language": get_language_from_filename(safe_path)
                            or "unknown",
                        }
                    )
                scan = await scan_service._process_and_launch_scan(
                    files_data=files_data, **common_kwargs
                )
            else:
                assert payload.repo_url is not None
                # V12.3.1 — defensive guard even though schema already enforces https://.
                if not payload.repo_url.lower().startswith("https://"):
                    raise ValueError(
                        "repo_url must use the https:// scheme; http://, git://, "
                        "and ssh:// are not accepted."
                    )
                scan = await scan_service.create_scan_from_git(
                    repo_url=payload.repo_url, **common_kwargs
                )

        return {"scan_id": str(scan.id), "status": scan.status}
    except (ValueError, PermissionError):
        raise
    except Exception:
        logger.exception(
            "mcp.tool.unexpected_error", extra={"tool": "sccap_submit_scan"}
        )
        raise


@mcp.tool
async def sccap_get_scan_status(scan_id: str) -> Dict[str, Any]:
    """Get the current status of a scan."""
    try:
        async with AsyncSessionLocal() as session:
            user = await _current_user(session)
            logger.info(
                "mcp.tool.invoke",
                extra={
                    "tool": "sccap_get_scan_status",
                    "user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "scan_id": scan_id,
                },
            )
            scan_service = _build_query_service(ScanRepository(session))
            scan = await scan_service.get_scan_status(uuid.UUID(scan_id), user)
            if scan.user_id != user.id and not user.is_superuser:
                logger.warning(
                    "mcp.authz.denied",
                    extra={
                        "tool": "sccap_get_scan_status",
                        "user_id": str(user.id),
                        "resource_id": scan_id,
                    },
                )
                raise PermissionError("Not authorized to view this scan.")
            return {
                "scan_id": str(scan.id),
                "project_id": str(scan.project_id),
                "status": scan.status,
                "scan_type": scan.scan_type,
                "cost_details": scan.cost_details,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": (
                    scan.completed_at.isoformat() if scan.completed_at else None
                ),
            }
    except (ValueError, PermissionError):
        raise
    except Exception:
        logger.exception(
            "mcp.tool.unexpected_error", extra={"tool": "sccap_get_scan_status"}
        )
        raise


@mcp.tool
async def sccap_get_scan_result(scan_id: str) -> Dict[str, Any]:
    """Fetch the final findings + summary for a completed scan. Returns
    an error dict if the scan is still running."""
    try:
        async with AsyncSessionLocal() as session:
            user = await _current_user(session)
            logger.info(
                "mcp.tool.invoke",
                extra={
                    "tool": "sccap_get_scan_result",
                    "user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "scan_id": scan_id,
                },
            )
            scan_service = _build_query_service(ScanRepository(session))
            scan = await scan_service.get_scan_status(uuid.UUID(scan_id), user)
            if scan.user_id != user.id and not user.is_superuser:
                logger.warning(
                    "mcp.authz.denied",
                    extra={
                        "tool": "sccap_get_scan_result",
                        "user_id": str(user.id),
                        "resource_id": scan_id,
                    },
                )
                raise PermissionError("Not authorized to view this scan.")
            # `get_scan_result` requires a `user` positional arg for the
            # ownership check. The pre-split MCP code omitted it (latent
            # crash) — we restore the correct call signature here as part
            # of the split. The auth check at line above already gates this
            # tool to the scan owner / superuser, so the inline check
            # inside `get_scan_result` is defense-in-depth.
            result = await scan_service.get_scan_result(uuid.UUID(scan_id), user)
            # get_scan_result returns a pydantic model; expose as plain dict.
            return (
                result.model_dump(mode="json")
                if hasattr(result, "model_dump")
                else result
            )
    except (ValueError, PermissionError):
        raise
    except Exception:
        logger.exception(
            "mcp.tool.unexpected_error", extra={"tool": "sccap_get_scan_result"}
        )
        raise


@mcp.tool
async def sccap_approve_scan(scan_id: str) -> Dict[str, Any]:
    """Approve a PENDING_COST_APPROVAL scan. Releases the full analysis
    via the Phase I.1 `interrupt() / Command(resume=...)` path."""
    try:
        async with AsyncSessionLocal() as session:
            user = await _current_user(session)
            logger.info(
                "mcp.tool.invoke",
                extra={
                    "tool": "sccap_approve_scan",
                    "user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "scan_id": scan_id,
                },
            )
            repo = ScanRepository(session)
            # V08.2.2 / V08.4.1 — explicit ownership check at MCP boundary.
            query = _build_query_service(repo)
            scan = await query.get_scan_status(uuid.UUID(scan_id), user)
            if scan.user_id != user.id and not user.is_superuser:
                logger.warning(
                    "mcp.authz.denied",
                    extra={
                        "tool": "sccap_approve_scan",
                        "user_id": str(user.id),
                        "resource_id": scan_id,
                    },
                )
                raise PermissionError("Not authorized to approve this scan.")
            scan_service = _build_lifecycle_service(repo)
            await scan_service.approve_scan(uuid.UUID(scan_id), user=user)
            return {"scan_id": scan_id, "approved": True}
    except (ValueError, PermissionError):
        raise
    except Exception:
        logger.exception(
            "mcp.tool.unexpected_error", extra={"tool": "sccap_approve_scan"}
        )
        raise


@mcp.tool
async def sccap_apply_fixes(scan_id: str, finding_ids: List[int]) -> Dict[str, Any]:
    """Apply AI-suggested fixes from a completed SUGGEST-mode scan.

    ``finding_ids`` is REQUIRED — the underlying service rejects an empty list
    (it has no concept of "apply all"). Pass the list of finding ids returned
    by ``sccap_get_scan_result``.  Maximum 1000 ids per request.
    """
    try:
        if not finding_ids:
            raise ValueError("finding_ids must be a non-empty list of finding ids.")
        if len(finding_ids) > 1000:
            raise ValueError("finding_ids must contain at most 1000 ids per request.")
        async with AsyncSessionLocal() as session:
            user = await _current_user(session)
            logger.info(
                "mcp.tool.invoke",
                extra={
                    "tool": "sccap_apply_fixes",
                    "user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "scan_id": scan_id,
                },
            )
            repo = ScanRepository(session)
            # V08.2.2 / V08.4.1 — explicit ownership check at MCP boundary.
            query = _build_query_service(repo)
            scan = await query.get_scan_status(uuid.UUID(scan_id), user)
            if scan.user_id != user.id and not user.is_superuser:
                logger.warning(
                    "mcp.authz.denied",
                    extra={
                        "tool": "sccap_apply_fixes",
                        "user_id": str(user.id),
                        "resource_id": scan_id,
                    },
                )
                raise PermissionError("Not authorized to apply fixes on this scan.")
            scan_service = _build_lifecycle_service(repo)
            applied = await scan_service.apply_selective_fixes(
                uuid.UUID(scan_id), finding_ids=finding_ids, user=user
            )
            return {"scan_id": scan_id, "applied": applied}
    except (ValueError, PermissionError):
        raise
    except Exception:
        logger.exception(
            "mcp.tool.unexpected_error", extra={"tool": "sccap_apply_fixes"}
        )
        raise


@mcp.tool
async def sccap_ask_advisor(payload: AskAdvisorInput) -> Dict[str, Any]:
    """One-shot advisor query — skips session persistence. Returns the
    agent's answer + cost/tokens for tracking."""
    try:
        async with AsyncSessionLocal() as session:
            user = await _current_user(session)
            logger.info(
                "mcp.tool.invoke",
                extra={
                    "tool": "sccap_ask_advisor",
                    "user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "scan_id": None,
                },
            )

            # Resolve LLM config: explicit override > user's most recent
            # chat session config > first available config.
            llm_config_id: Optional[uuid.UUID] = None
            if payload.llm_config_id:
                llm_config_id = uuid.UUID(payload.llm_config_id)
            else:
                chat_repo = ChatRepository(session)
                sessions = await chat_repo.get_sessions_for_user(user.id)
                if sessions and sessions[0].llm_config_id:
                    llm_config_id = sessions[0].llm_config_id

            from app.infrastructure.agents.chat_agent import ChatAgent

            agent = ChatAgent()
            (content, _llm_interaction_id, cost) = await agent.generate_response(
                session_id=uuid.uuid4(),  # ephemeral — not persisted
                user_question=payload.question,
                history=[],
                llm_config_id=llm_config_id,
                frameworks=payload.frameworks or [],
            )

            # Keep user reference warm for the type-checker on sessions without
            # follow-up queries.
            _ = user
            _ = settings

            return {"answer": content, "cost_usd": cost}
    except (ValueError, PermissionError):
        raise
    except Exception:
        logger.exception(
            "mcp.tool.unexpected_error", extra={"tool": "sccap_ask_advisor"}
        )
        raise
