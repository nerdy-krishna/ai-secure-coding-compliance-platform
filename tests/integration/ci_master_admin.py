"""Provision the stable master-admin invariant for the disposable CI stack.

The integration suite inserts users directly instead of running the product
setup wizard. Production refuses identity deletion unless the persisted master
admin identifier exists, so CI must establish that invariant explicitly. This
fixture never replaces an existing master-admin configuration and cleanup only
removes the exact disposable identity it created.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets

from fastapi_users.password import PasswordHelper
from sqlalchemy import select

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    RoleAssignment,
    SystemConfiguration,
    User,
)
from app.shared.lib.permissions import PLATFORM_OWNER


MASTER_KEY = "security.master_admin_user_id"
FIXTURE_EMAIL = "ci-integration-master-admin@example.com"


def _require_integration_mode() -> None:
    if os.getenv("SCCAP_RUN_INTEGRATION") != "1":
        raise RuntimeError("ci_master_admin requires SCCAP_RUN_INTEGRATION=1")


async def _setup() -> None:
    _require_integration_mode()
    async with AsyncSessionLocal() as db:
        configured = await db.get(SystemConfiguration, MASTER_KEY)
        if configured is not None:
            print(json.dumps({"created": False, "reason": "already_configured"}))
            return

        user = await db.scalar(select(User).where(User.email == FIXTURE_EMAIL))
        if user is None:
            user = User(
                email=FIXTURE_EMAIL,
                hashed_password=PasswordHelper().hash(secrets.token_urlsafe(48)),
                is_active=True,
                is_superuser=True,
                is_verified=True,
                tenant_id=None,
            )
            db.add(user)
            await db.flush()
            db.add(
                RoleAssignment(
                    user_id=user.id,
                    tenant_id=None,
                    role_key=PLATFORM_OWNER,
                )
            )

        db.add(
            SystemConfiguration(
                key=MASTER_KEY,
                value={"user_id": int(user.id)},
                description="Disposable master admin for CI integration contracts.",
                is_secret=False,
                encrypted=False,
            )
        )
        user_id = int(user.id)
        await db.commit()
        print(json.dumps({"created": True, "user_id": user_id}))


async def _cleanup() -> None:
    _require_integration_mode()
    async with AsyncSessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == FIXTURE_EMAIL))
        configured = await db.get(SystemConfiguration, MASTER_KEY)
        if user is None or configured is None:
            print(json.dumps({"removed": False, "reason": "fixture_not_active"}))
            return
        if int(configured.value.get("user_id", -1)) != int(user.id):
            print(json.dumps({"removed": False, "reason": "configuration_not_owned"}))
            return

        user_id = int(user.id)
        await db.delete(configured)
        await db.delete(user)
        await db.commit()
        print(json.dumps({"removed": True, "user_id": user_id}))


async def _run(action: str) -> None:
    try:
        if action == "setup":
            await _setup()
        else:
            await _cleanup()
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("setup", "cleanup"))
    args = parser.parse_args()
    asyncio.run(_run(args.action))


if __name__ == "__main__":
    main()
