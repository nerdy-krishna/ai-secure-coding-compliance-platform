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


@pytest.fixture(autouse=True)
def _coverage_does_not_touch_the_database(monkeypatch):
    """Same reason as `_facts_do_not_touch_the_database`: the ledger read belongs to the loop.

    Tests that care about coverage call `classify_gaps` / `render_for_prompt` directly, which
    are pure functions; nothing in a unit test needs the table.
    """
    from app.pentest import coverage as coverage_mod

    async def _no_rows(_run_id):
        return []

    monkeypatch.setattr(coverage_mod, "rows", _no_rows)
    yield


@pytest.fixture(autouse=True)
def _goals_do_not_touch_the_database_or_the_model(monkeypatch):
    """Goals are read into every prompt and decomposed once per run — neither belongs in a unit
    test of the loop. Tests that exercise the goals role call `goals.render` / `goals.decompose`
    directly with their own fakes.
    """
    from app.pentest import goals as goals_mod

    async def _no_rows(_run_id):
        return []

    async def _no_block(_run_id):
        return ""

    async def _no_decompose(*_args, **_kwargs):
        return None

    monkeypatch.setattr(goals_mod, "rows", _no_rows)
    monkeypatch.setattr(goals_mod, "render_for_prompt", _no_block)
    monkeypatch.setattr(goals_mod, "decompose", _no_decompose)
    yield
