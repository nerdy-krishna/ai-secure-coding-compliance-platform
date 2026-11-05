"""Inventory sweep: refresh what the assets are, then apply a CVE list.

The sweep used to carry its own fingerprinter — a smaller, older HTTP-only probe that
bypassed the pentest engine and skipped any asset without a recorded endpoint. Two
implementations of "find out what this asset is" drifted apart; this one calls the good
one.

A sweep is therefore exactly: **probe (rescan) then check**.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from uuid import UUID

logger = logging.getLogger(__name__)


async def run_sweep(
    *,
    tenant_id: UUID,
    asset_ids: Optional[list[UUID]] = None,
    cve_ids: Optional[list[str]] = None,
    verify: bool = False,
    max_verifications: int = 25,
) -> dict[str, Any]:
    """Refresh the inventory's fingerprints, then apply the CVE list to it."""
    from app.assets import service as asset_service

    probe = await asset_service.probe_inventory(
        tenant_id=tenant_id, asset_ids=asset_ids, rescan=True
    )
    outcome = await asset_service.check_cves(
        tenant_id=tenant_id,
        cve_ids=cve_ids,
        asset_ids=asset_ids,
        verify=verify,
        max_verifications=max_verifications,
    )
    return {
        "probe": probe,
        "endpoints_fingerprinted": probe.get("endpoints_probed", 0),
        "fingerprints_found": probe.get("fingerprints_found", 0),
        "queued": probe.get("queued", 0),
        **outcome,
    }
