"""Single baseline schema for a fresh install.

better-pentester: the entire database is created from one snapshot instead of
the historical, interleaved migration chain. The snapshot is a plain
``pg_dump --schema-only`` of the target schema (SAST ledger + the three new
pentest tables); it already excludes the dropped pentest graph and the alembic
version table.

The dump is split into individual statements (respecting dollar-quoted function
bodies and single-quoted literals) and executed one at a time over the asyncpg
connection, which does not accept multi-statement batches.

Revision ID: baseline0001
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Union

from alembic import op

revision: str = "baseline0001"
down_revision: Union[str, None] = None
branch_labels = None
depends_on = None

_DOLLAR_TAG = re.compile(r"\$[A-Za-z0-9_]*\$")


def _split_statements(sql: str) -> list[str]:
    """Split pg_dump output on top-level semicolons.

    Handles dollar-quoted function bodies (``$$ ... $$``, ``$_$ ... $_$``,
    ``$tag$ ... $tag$``), single-quoted literals, and ``--`` line comments so a
    semicolon inside any of them never terminates a statement.
    """
    statements: list[str] = []
    current: list[str] = []
    dollar: str | None = None
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if dollar is not None:
            if sql.startswith(dollar, i):
                current.append(dollar)
                i += len(dollar)
                dollar = None
            else:
                current.append(ch)
                i += 1
            continue
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            # line comment: skip to the next newline, preserving the newline
            while i < n and sql[i] != "\n":
                i += 1
            continue
        if ch == "$":
            m = _DOLLAR_TAG.match(sql, i)
            if m:
                dollar = m.group(0)
                current.append(dollar)
                i += len(dollar)
                continue
        if ch == "'":
            current.append(ch)
            i += 1
            while i < n:
                current.append(sql[i])
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        current.append(sql[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == ";":
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def _load_sql() -> str:
    path = Path(__file__).resolve().parent.parent / "baseline_schema.sql"
    return path.read_text(encoding="utf-8")


def upgrade() -> None:
    sql = _load_sql()
    bind = op.get_bind()
    for statement in _split_statements(sql):
        # The dump pins an empty search_path so every object reference is
        # schema-qualified during a pg_restore. Running it here would leave the
        # connection unable to find the (unqualified) alembic_version table that
        # Alembic stamps afterwards, so it is skipped.
        if statement.startswith("SELECT pg_catalog.set_config('search_path'"):
            continue
        bind.execute(statement)


def downgrade() -> None:
    raise RuntimeError("baseline schema is not reversible")
