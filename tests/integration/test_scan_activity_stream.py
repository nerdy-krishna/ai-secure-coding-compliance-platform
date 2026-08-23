"""Public SSE replay contract for the versioned scan activity envelope."""

from __future__ import annotations

import json
import os
import re
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    Project,
    RoleAssignment,
    Scan,
    ScanEvent,
    User,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import STATUS_COMPLETED
from app.shared.lib.permissions import ANALYST
from tests.integration.support import integration_test


@integration_test
class ScanActivityStreamIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        self.email = f"integration-activity-{uuid4()}@example.com"
        self.password = f"A7!{uuid4()}z"
        async with AsyncSessionLocal() as db:
            user = User(
                email=self.email,
                hashed_password=PasswordHelper().hash(self.password),
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(user)
            await db.flush()
            db.add(
                RoleAssignment(
                    user_id=user.id,
                    tenant_id=user.tenant_id,
                    role_key=ANALYST,
                )
            )
            project = Project(user_id=user.id, name=f"activity-{uuid4()}")
            scan = Scan(
                project=project,
                user_id=user.id,
                scan_type="AUDIT",
                status=STATUS_COMPLETED,
                frameworks=[],
                summary={},
            )
            db.add_all([project, scan])
            await db.commit()
            repo = ScanRepository(db)
            await repo.create_scan_event(scan.id, "SCANNER_BANDIT", "STARTED")
            await repo.create_scan_event(
                scan.id,
                "SCANNER_BANDIT",
                "COMPLETED",
                details={"scanner": "bandit", "source_code": "never expose me"},
            )
            await repo.create_scan_event(scan.id, "COMPLETED", "COMPLETED")
            rows = (
                await db.scalars(
                    select(ScanEvent)
                    .where(ScanEvent.scan_id == scan.id)
                    .order_by(ScanEvent.id)
                )
            ).all()
            self.cursor = rows[0].id
            self.expected_ids = [row.id for row in rows[1:]]
            self.user_id = user.id
            self.project_id = project.id
            self.scan_id = scan.id
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).delete_project(self.project_id)
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id == self.user_id)
            )
            await db.execute(delete(User).where(User.id == self.user_id))
            await db.commit()
        await engine.dispose()

    async def _stream_token(self) -> str:
        login = await self.client.post(
            "/api/v1/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200, login.text)
        issued = await self.client.post(
            f"/api/v1/scans/{self.scan_id}/stream-token",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        return issued.json()["access_token"]

    async def test_reconnect_cursor_replays_each_unseen_activity_once(self) -> None:
        token = await self._stream_token()
        response = await self.client.get(
            f"/api/v1/scans/{self.scan_id}/stream",
            params={"access_token": token, "cursor": str(self.cursor)},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payloads = [
            json.loads(raw)
            for raw in re.findall(
                r"event: scan_event\nid: \d+\ndata: (.+)\n\n", response.text
            )
        ]
        self.assertEqual([item["event_id"] for item in payloads], self.expected_ids)
        self.assertEqual(len({item["cursor"] for item in payloads}), len(payloads))
        self.assertTrue(all(item["schema_version"] == 1 for item in payloads))
        self.assertTrue(all("activity_kind" in item for item in payloads))
        self.assertNotIn("never expose me", response.text)

    async def test_invalid_cursor_is_rejected(self) -> None:
        token = await self._stream_token()
        response = await self.client.get(
            f"/api/v1/scans/{self.scan_id}/stream",
            params={"access_token": token, "cursor": "not-an-integer"},
        )
        self.assertEqual(response.status_code, 400, response.text)


if __name__ == "__main__":
    unittest.main()
