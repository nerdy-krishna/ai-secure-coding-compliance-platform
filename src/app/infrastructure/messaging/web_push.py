"""Web Push delivery (#90 / PRD #83).

Sends scan-completion desktop notifications via the Web Push protocol
so they fire even when the SCCAP browser tab is closed. VAPID-signed,
RFC-8291-encrypted delivery is handled by `pywebpush`.

Web Push is **optional**: when the VAPID keypair is unconfigured every
function here is a safe no-op and the app falls back to the in-app +
tab-open desktop notifications (#89). The blocking `pywebpush.webpush`
call is always run off the event loop via `asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from functools import lru_cache
from typing import Any, Dict, Optional

from sqlalchemy import delete, select

from app.config.config import settings
from app.shared.lib.scan_status import (
    STATUS_BLOCKED_PRE_LLM,
    STATUS_BLOCKED_USER_DECLINE,
    STATUS_COMPLETED,
    STATUS_REMEDIATION_COMPLETED,
)

logger = logging.getLogger(__name__)


def is_web_push_enabled() -> bool:
    """True only when a VAPID keypair is configured."""
    return bool(
        (settings.VAPID_PRIVATE_KEY or "").strip()
        and (settings.VAPID_PUBLIC_KEY or "").strip()
    )


def vapid_public_key() -> Optional[str]:
    """The browser `applicationServerKey`, or None when disabled."""
    key = (settings.VAPID_PUBLIC_KEY or "").strip()
    return key or None


@lru_cache(maxsize=1)
def _vapid() -> Any:
    """The cached py-vapid signer built from the raw private key."""
    from py_vapid import Vapid02

    return Vapid02.from_raw(settings.VAPID_PRIVATE_KEY.strip().encode())


def _send_sync(subscription_info: Dict[str, Any], payload: Dict[str, Any]) -> bool:
    """Blocking single send. Returns False ONLY for a permanently-gone
    subscription (404 / 410) so the caller prunes it; transient errors
    return True (keep the subscription, retry next time)."""
    from pywebpush import WebPushException, webpush

    try:
        webpush(
            subscription_info=subscription_info,
            data=json.dumps(payload),
            vapid_private_key=_vapid(),
            vapid_claims={"sub": settings.VAPID_SUBJECT or "mailto:admin@sccap.local"},
            ttl=600,
        )
        return True
    except WebPushException as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status in (404, 410):
            return False
        logger.warning("web_push: transient send failure (status=%s)", status)
        return True
    except Exception:  # noqa: BLE001
        logger.warning("web_push: unexpected send error", exc_info=True)
        return True


async def send_web_push(
    subscription_info: Dict[str, Any], payload: Dict[str, Any]
) -> bool:
    """Send one Web Push off the event loop. False ⇒ prune the sub."""
    if not is_web_push_enabled():
        return True
    return await asyncio.to_thread(_send_sync, subscription_info, payload)


async def notify_scan_completed(scan_id: Any) -> None:
    """Deliver a scan-completion Web Push to the scan owner.

    Loads the scan owner's push subscriptions, sends to each, and
    prunes any that the push service reports as gone. A no-op when Web
    Push is disabled or the owner has no subscriptions. Best-effort —
    never raises into the caller.
    """
    if not is_web_push_enabled():
        return
    try:
        from app.infrastructure.database import AsyncSessionLocal
        from app.infrastructure.database import models as db_models

        async with AsyncSessionLocal() as db:
            scan = (
                await db.execute(
                    select(db_models.Scan).where(db_models.Scan.id == scan_id)
                )
            ).scalar_one_or_none()
            if scan is None:
                return
            subs = (
                (
                    await db.execute(
                        select(db_models.PushSubscription).where(
                            db_models.PushSubscription.user_id == scan.user_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            if not subs:
                return
            project_name = (
                await db.execute(
                    select(db_models.Project.name).where(
                        db_models.Project.id == scan.project_id
                    )
                )
            ).scalar_one_or_none() or "Project"

            status = scan.status
            if status in (STATUS_COMPLETED, STATUS_REMEDIATION_COMPLETED):
                outcome = "completed"
            elif status in (STATUS_BLOCKED_PRE_LLM, STATUS_BLOCKED_USER_DECLINE):
                outcome = "blocked"
            else:
                outcome = "failed"

            payload = {
                "title": "SCCAP — Scan finished",
                "body": f"{project_name} — scan {outcome}",
                "url": f"/analysis/results/{scan_id}",
                # Per-scan tag — collapses against the in-page
                # notification (#89) so a focused user sees one popup.
                "tag": str(scan_id),
            }

            dead: list[str] = []
            for sub in subs:
                ok = await send_web_push(
                    {
                        "endpoint": sub.endpoint,
                        "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
                    },
                    payload,
                )
                if not ok:
                    dead.append(sub.endpoint)

            if dead:
                await db.execute(
                    delete(db_models.PushSubscription).where(
                        db_models.PushSubscription.endpoint.in_(dead)
                    )
                )
                await db.commit()
                logger.info("web_push: pruned %d dead subscription(s)", len(dead))
    except Exception:  # noqa: BLE001
        logger.warning("web_push: notify_scan_completed failed", exc_info=True)
