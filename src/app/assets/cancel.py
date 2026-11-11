"""Asking a running inventory check to stop.

A CVE check runs inside the API request that started it (research, corpus lookups, probes,
matching, optional detection tests), so it has no job row to cancel. What it can have is a
cooperative flag: the operator presses Stop, the flag is set, and the check stops at its next
safe boundary instead of probing another dozen assets.

This is deliberately in-process. The API runs one process and the check runs in it, so a set
of tenant ids is enough; if that ever becomes a worker pool, this becomes a table with a
"requested at" column.
"""

from __future__ import annotations

import logging
from uuid import UUID

logger = logging.getLogger(__name__)

_STOPPED: set[UUID] = set()


class CheckStopped(Exception):
    """Raised inside a check that the operator asked to stop."""


def request(tenant_id: UUID) -> None:
    _STOPPED.add(tenant_id)
    logger.info("stop requested for inventory checks of tenant %s", tenant_id)


def clear(tenant_id: UUID) -> None:
    _STOPPED.discard(tenant_id)


def requested(tenant_id: UUID) -> bool:
    return tenant_id in _STOPPED


def check(tenant_id: UUID) -> None:
    """Raise if a stop has been requested — call this between units of work."""
    if requested(tenant_id):
        raise CheckStopped("stopped by the operator")
