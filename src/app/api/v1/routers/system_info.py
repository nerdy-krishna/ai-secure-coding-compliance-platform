"""Build/version reporting and release checking.

Two small endpoints that let an operator answer "what am I running, and is there
a newer release?" without shelling into the host:

* ``GET /system/version``      — what this build is (commit, build time, version,
                                 migration head). Any signed-in user may read it;
                                 it is needed by the UI footer and diagnostics.
* ``GET /system/update-check`` — superuser only. Compares the running commit to
                                 the newest GitHub release, cached in-process.

Deliberately read-only: nothing here updates anything. The actual upgrade stays
a deliberate host action (``./setup.sh --update``), so a compromised admin
session cannot replace the platform's code.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

import httpx
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.infrastructure.auth.core import current_active_user, current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/system")

#: Handshake directory bind-mounted from the host (see docker-compose.yml).
#: The API can only *request* an update here; the host systemd unit executes it.
CONTROL_DIR = Path(os.environ.get("SCCAP_CONTROL_DIR", "/control"))
REQUEST_FILE = CONTROL_DIR / "update-request"
STATUS_FILE = CONTROL_DIR / "update-status.json"
LOG_FILE = CONTROL_DIR / "update.log"
LOG_TAIL_BYTES = 6000

#: In-process cache for the GitHub lookup so a UI poll cannot rate-limit us.
_UPDATE_CACHE_TTL_SECONDS = 3600
_update_cache: dict[str, Any] = {"checked_at": 0.0, "value": None}

_RELEASE_REPO = os.environ.get(
    "SCCAP_RELEASE_REPO", "nerdy-krishna/ai-secure-coding-compliance-platform"
)
#: Commit-ish baked into the image at build time; empty on a bare `docker run`.
_BUILD_COMMIT = os.environ.get("SCCAP_BUILD_COMMIT", "").strip()
_BUILD_TIME = os.environ.get("SCCAP_BUILD_TIME", "").strip()
_BUILD_VERSION = os.environ.get("SCCAP_BUILD_VERSION", "").strip()


def running_version() -> str:
    if _BUILD_VERSION:
        return _BUILD_VERSION
    try:  # pyproject declares the distribution version
        from importlib.metadata import version as _dist_version

        return _dist_version("app")
    except Exception:  # pragma: no cover - metadata not installed
        return "unknown"


def running_commit() -> str:
    """Commit the image was built from, else the checkout's HEAD."""

    if _BUILD_COMMIT:
        return _BUILD_COMMIT
    for candidate in (".git/HEAD", "../.git/HEAD"):
        try:
            with open(candidate, encoding="utf-8") as handle:
                head = handle.read().strip()
        except OSError:
            continue
        if head.startswith("ref: "):
            ref_path = os.path.join(os.path.dirname(candidate), head[5:].strip())
            try:
                with open(ref_path, encoding="utf-8") as handle:
                    return handle.read().strip()
            except OSError:
                continue
        if head:
            return head
    return ""


async def _migration_head(db: AsyncSession) -> Optional[str]:
    try:
        result = await db.execute(text("select version_num from alembic_version"))
        return result.scalar()
    except Exception:  # pragma: no cover - pre-migration database
        return None


@router.get("/version")
async def get_version(
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_active_user),
) -> dict[str, Any]:
    """Report the running build so the UI and support can identify it."""

    return {
        "version": running_version(),
        "commit": running_commit(),
        "built_at": _BUILD_TIME or None,
        "environment": str(settings.ENVIRONMENT),
        "migration_head": await _migration_head(db),
    }


def _is_newer(latest_tag: str, current_version: str) -> bool:
    """True when ``latest_tag`` (e.g. v1.4.0) is ahead of the running version."""

    def _parse(value: str) -> tuple[int, ...]:
        cleaned = value.strip().lstrip("vV")
        parts: list[int] = []
        for chunk in cleaned.split("."):
            digits = "".join(ch for ch in chunk if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)

    try:
        return _parse(latest_tag) > _parse(current_version)
    except Exception:  # pragma: no cover - defensive
        return False


async def _fetch_latest_release() -> dict[str, Any]:
    now = time.time()
    cached = _update_cache.get("value")
    if (
        cached is not None
        and now - float(_update_cache.get("checked_at") or 0)
        < _UPDATE_CACHE_TTL_SECONDS
    ):
        return cached

    payload: dict[str, Any] = {
        "checked": False,
        "release_repo": _RELEASE_REPO,
        "latest_tag": None,
        "latest_url": None,
        "published_at": None,
        "notes_excerpt": None,
        "error": None,
    }
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(
                f"https://api.github.com/repos/{_RELEASE_REPO}/releases/latest",
                headers={"Accept": "application/vnd.github+json"},
            )
        if response.status_code == 404:
            payload["checked"] = True
            payload["error"] = "no_releases"
        elif response.status_code >= 400:
            payload["error"] = f"github_status_{response.status_code}"
        else:
            data = response.json()
            body = (data.get("body") or "").strip()
            payload.update(
                {
                    "checked": True,
                    "latest_tag": data.get("tag_name"),
                    "latest_url": data.get("html_url"),
                    "published_at": data.get("published_at"),
                    "notes_excerpt": body[:400] or None,
                }
            )
    except Exception as exc:  # offline installs are normal; never fail the request
        logger.info(
            "http.update_check.unavailable", extra={"error": type(exc).__name__}
        )
        payload["error"] = "network_unavailable"

    _update_cache["value"] = payload
    _update_cache["checked_at"] = now
    return payload


def _read_status() -> dict[str, Any]:
    """Current update phase as published by the host runner."""

    default: dict[str, Any] = {
        "phase": "idle",
        "message": None,
        "updated_at": None,
        "from_commit": None,
        "to_commit": None,
        "exit_code": None,
        "log_tail": None,
        "request_pending": REQUEST_FILE.exists(),
        "runner_available": CONTROL_DIR.is_dir(),
    }
    try:
        raw = STATUS_FILE.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return default
    default.update({k: payload.get(k) for k in default if k in payload})
    try:
        with LOG_FILE.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - LOG_TAIL_BYTES))
            default["log_tail"] = handle.read().decode("utf-8", "replace")
    except OSError:
        pass
    return default


@router.post("/update", status_code=status.HTTP_202_ACCEPTED)
async def request_update(
    _admin: db_models.User = Depends(current_superuser),
) -> dict[str, Any]:
    """Ask the host to run ``setup.sh --update`` (superuser only).

    Nothing here executes code: the request is a file the operator's own systemd
    unit watches, so the privilege boundary stays on the host.
    """

    current = _read_status()
    if not CONTROL_DIR.is_dir():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Update runner is not available on this deployment. "
                "Run ./setup.sh --update on the host."
            ),
        )
    if current.get("phase") == "running" or REQUEST_FILE.exists():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An update is already in progress.",
        )
    try:
        CONTROL_DIR.mkdir(parents=True, exist_ok=True)
        REQUEST_FILE.write_text(
            json.dumps(
                {
                    "requested_by": int(getattr(_admin, "id", 0) or 0),
                    "requested_at": datetime.now(tz=timezone.utc).isoformat(),
                }
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Could not hand the request to the host runner ({type(exc).__name__}).",
        ) from exc
    logger.info(
        "system.update.requested",
        extra={"user_id": getattr(_admin, "id", None)},
    )
    return _read_status()


@router.get("/update-status")
async def update_status(
    _admin: db_models.User = Depends(current_superuser),
) -> dict[str, Any]:
    """Progress of a UI-triggered (or host-run) update."""

    return _read_status()


@router.get("/update-check")
async def check_for_updates(
    _admin: db_models.User = Depends(current_superuser),
) -> dict[str, Any]:
    """Report whether a newer published release exists. Never performs an update."""

    info = await _fetch_latest_release()
    current = running_version()
    latest_tag = info.get("latest_tag")
    return {
        "current_version": current,
        "current_commit": running_commit(),
        "latest_tag": latest_tag,
        "latest_url": info.get("latest_url"),
        "published_at": info.get("published_at"),
        "notes_excerpt": info.get("notes_excerpt"),
        "update_available": bool(latest_tag and _is_newer(latest_tag, current)),
        "release_repo": info.get("release_repo"),
        "checked": info.get("checked", False),
        "error": info.get("error"),
        "update_command": "./setup.sh --update",
    }
