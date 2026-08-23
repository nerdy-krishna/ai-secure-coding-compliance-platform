"""Operator-only admin scripts.

These modules MUST NOT be imported by any router, MCP tool, or
production code path. They run via
``docker compose exec app python -m app.scripts.<module>`` and
require shell access to the worker host.
"""
