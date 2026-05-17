"""`validate_framework_selection` — submitted framework names must be
configured in the DB.

Regression guard: scan submission and chat-session creation used to
validate against a hardcoded allow-list of the original five
frameworks, which silently rejected CWE Essentials, ISVS, and any
admin-added custom framework. Validation now reads the live
`frameworks` table.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from app.infrastructure.database import models as db_models
from app.shared.lib.framework_validation import validate_framework_selection

# Test-only framework names — underscore-prefixed so they cannot collide
# with a real seeded framework whether the DB is empty (CI) or already
# seeded (local dev).
_FW_A = "_t_framework_a"
_FW_B = "_t_framework_b"
_FW_ABSENT = "_t_framework_absent"


async def _add_frameworks(db_session, *names: str) -> None:
    for name in names:
        db_session.add(
            db_models.Framework(
                id=uuid.uuid4(), name=name, description=f"{name} framework"
            )
        )
    await db_session.flush()


@pytest.mark.asyncio
async def test_configured_frameworks_pass(db_session):
    await _add_frameworks(db_session, _FW_A, _FW_B)
    # No raise — every name exists in the frameworks table.
    await validate_framework_selection(db_session, [_FW_A])
    await validate_framework_selection(db_session, [_FW_A, _FW_B])


@pytest.mark.asyncio
async def test_unknown_framework_is_rejected(db_session):
    await _add_frameworks(db_session, _FW_A)
    with pytest.raises(HTTPException) as exc:
        await validate_framework_selection(db_session, [_FW_A, _FW_ABSENT])
    assert exc.value.status_code == 400
    assert _FW_ABSENT in exc.value.detail


@pytest.mark.asyncio
async def test_empty_selection_rejected_by_default(db_session):
    with pytest.raises(HTTPException) as exc:
        await validate_framework_selection(db_session, [])
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_empty_selection_allowed_when_not_required(db_session):
    # Chat sessions may be created with no frameworks (general Q&A).
    await validate_framework_selection(db_session, [], require_non_empty=False)
