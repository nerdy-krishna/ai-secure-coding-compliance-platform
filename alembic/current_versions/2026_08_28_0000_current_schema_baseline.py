"""Establish the SCCAP current-schema migration baseline.

Revision ID: 4d5e6f708192
Revises:
Create Date: 2026-08-28 00:00:00

The revision identifier intentionally matches the final revision in the
archived chain. Databases already upgraded to that revision require no stamp
or DDL. Empty databases execute the frozen schema snapshot referenced below.
"""

from __future__ import annotations

from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
import re

from alembic import op
import sqlalchemy as sa


revision: str = "4d5e6f708192"
down_revision: None = None
branch_labels: None = None
depends_on: None = None

_BASELINE_PATH = (
    Path(__file__).resolve().parents[1]
    / "baselines"
    / "2026_08_28_current_schema.sql"
)
_BASELINE_SHA256 = (
    "89f040bcfedf596accac05d06bdc57bd53a69c4b2a5c6e9bd13a5f1d6bb8616b"
)
_DOLLAR_QUOTE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")


def _iter_sql_statements(sql: str) -> Iterator[str]:
    """Split frozen PostgreSQL SQL without breaking quoted function bodies."""

    buffer: list[str] = []
    index = 0
    state = "normal"
    dollar_tag: str | None = None
    block_comment_depth = 0

    while index < len(sql):
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""

        if state == "line_comment":
            buffer.append(char)
            index += 1
            if char == "\n":
                state = "normal"
            continue

        if state == "block_comment":
            if char == "/" and next_char == "*":
                buffer.extend((char, next_char))
                block_comment_depth += 1
                index += 2
            elif char == "*" and next_char == "/":
                buffer.extend((char, next_char))
                block_comment_depth -= 1
                index += 2
                if block_comment_depth == 0:
                    state = "normal"
            else:
                buffer.append(char)
                index += 1
            continue

        if state == "single_quote":
            buffer.append(char)
            index += 1
            if char == "'":
                if index < len(sql) and sql[index] == "'":
                    buffer.append(sql[index])
                    index += 1
                else:
                    state = "normal"
            continue

        if state == "double_quote":
            buffer.append(char)
            index += 1
            if char == '"':
                if index < len(sql) and sql[index] == '"':
                    buffer.append(sql[index])
                    index += 1
                else:
                    state = "normal"
            continue

        if state == "dollar_quote":
            assert dollar_tag is not None
            if sql.startswith(dollar_tag, index):
                buffer.append(dollar_tag)
                index += len(dollar_tag)
                dollar_tag = None
                state = "normal"
            else:
                buffer.append(char)
                index += 1
            continue

        if char == "-" and next_char == "-":
            buffer.extend((char, next_char))
            index += 2
            state = "line_comment"
        elif char == "/" and next_char == "*":
            buffer.extend((char, next_char))
            index += 2
            block_comment_depth = 1
            state = "block_comment"
        elif char == "'":
            buffer.append(char)
            index += 1
            state = "single_quote"
        elif char == '"':
            buffer.append(char)
            index += 1
            state = "double_quote"
        elif char == "$":
            match = _DOLLAR_QUOTE.match(sql, index)
            if match is None:
                buffer.append(char)
                index += 1
            else:
                dollar_tag = match.group(0)
                buffer.append(dollar_tag)
                index = match.end()
                state = "dollar_quote"
        elif char == ";":
            statement = "".join(buffer).strip()
            buffer.clear()
            index += 1
            if statement:
                yield statement
        else:
            buffer.append(char)
            index += 1

    remainder = "".join(buffer).strip()
    if state != "normal" or remainder:
        raise ValueError("baseline SQL contains an unterminated statement")


def _read_verified_baseline() -> str:
    payload = _BASELINE_PATH.read_bytes()
    actual_hash = sha256(payload).hexdigest()
    if actual_hash != _BASELINE_SHA256:
        raise RuntimeError(
            "SCCAP baseline SQL digest mismatch; regenerate or review the "
            "snapshot and update the pinned digest explicitly"
        )
    return payload.decode("utf-8")


def upgrade() -> None:
    """Create the complete current schema on an empty PostgreSQL database."""

    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("the SCCAP baseline supports PostgreSQL only")
    for statement in _iter_sql_statements(_read_verified_baseline()):
        op.execute(sa.text(statement))


def downgrade() -> None:
    """The current-schema root is an explicit irreversible cutover."""

    raise RuntimeError(
        "the SCCAP current-schema baseline cannot be downgraded; restore a "
        "database backup or use the archived pre-baseline migration chain"
    )
