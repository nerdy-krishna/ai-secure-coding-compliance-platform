"""The inventory activity stream: shape, and the promise that it never breaks work."""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

from app.assets import events


def test_serialise_fills_the_console_contract():
    row = SimpleNamespace(
        id=42,
        check_id=uuid.uuid4(),
        level="warning",
        kind="match",
        message="CVE-2021-23017 → portal: undetermined",
        payload={"reason": "version only"},
        created_at=None,
    )

    line = events.serialise(row)

    assert line["id"] == 42
    assert line["level"] == "warning"
    assert line["kind"] == "match"
    assert line["payload"] == {"reason": "version only"}
    assert isinstance(line["check_id"], str)


def test_emit_never_raises_when_the_database_is_down(monkeypatch):
    """Observing the work must not be able to fail the work."""

    class Boom:
        def __call__(self):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(events, "AsyncSessionLocal", Boom())

    # No exception: the check that is being observed keeps running.
    asyncio.run(events.emit(uuid.uuid4(), "probing portal", kind="discovery"))


def test_unknown_levels_are_normalised(monkeypatch):
    captured = {}

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def add(self, row):
            captured["level"] = row.level
            captured["kind"] = row.kind
            captured["message"] = row.message

        async def commit(self):
            return None

    monkeypatch.setattr(events, "AsyncSessionLocal", lambda: FakeSession())

    asyncio.run(
        events.emit(uuid.uuid4(), "x", level="shouting", kind="discovery", payload=None)
    )

    assert captured["level"] == "info"
