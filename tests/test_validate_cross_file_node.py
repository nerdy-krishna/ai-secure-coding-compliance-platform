"""`validate_cross_file` node — opt-in gate (#81 / PRD #75).

The full opted-in path runs a reasoning-LLM call per eligible finding
and is covered at the unit level by `test_cross_file_validator.py`.
This file pins the opt-out contract: a scan that did not opt in must
see a byte-identical no-op from the node.
"""

from __future__ import annotations

import asyncio
import uuid

from app.infrastructure.workflows.nodes.validate_cross_file import (
    validate_cross_file_node,
)


def _run(state):
    return asyncio.run(validate_cross_file_node(state))


def test_opted_out_scan_is_a_no_op():
    """No `cross_file_validation` flag → empty patch, no findings touched."""
    state = {"scan_id": uuid.uuid4(), "cross_file_validation": False, "findings": []}
    assert _run(state) == {}


def test_missing_flag_is_treated_as_opted_out():
    state = {"scan_id": uuid.uuid4(), "findings": []}
    assert _run(state) == {}
