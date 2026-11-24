"""Make ``src`` importable for the tests without installing the package."""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _facts_do_not_touch_the_database(monkeypatch):
    """Keep the prompt's fact block out of the SQL layer during tests.

    The agent renders known facts into every prompt, which means one database read per turn.
    Tests that exercise the loop stub every other persistence module (memory, artifacts, plan,
    ledger), and a real read here would bind the shared async engine to whichever event loop
    the test happened to create — the next test then fails with "Future attached to a
    different loop". Tests that care about facts supply their own recorder.
    """
    from app.pentest import facts as facts_mod

    async def _empty(_run_id, **_kwargs):
        return []

    monkeypatch.setattr(facts_mod, "for_run", _empty)
    yield
