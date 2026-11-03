"""Asset inventory and CVE applicability API.

Two ideas hold this surface together:

- the inventory is the authorisation boundary — an in-scope asset is one whose hosts
  may be fingerprinted and probed, and the basis is recorded;
- every answer is a verdict with a basis, never a bare yes: `declared` (a dependency
  version), `observed` (a banner) or `probe` (a check the model designed and ran).
"""

from __future__ import annotations

import logging
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.assets import models as am
from app.assets import service
from app.infrastructure.auth.core import current_active_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["Assets"])


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(default=am.ASSET_WEB_APP)
    description: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=200)
    environment: Optional[str] = Field(default=None, max_length=32)
    in_scope: bool = True
    authorization_basis: Optional[str] = Field(
        default=None,
        description=(
            "Why this asset may be tested. Adding it to the inventory is the "
            "authorisation; this records who authorised it and on what basis."
        ),
    )


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    kind: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    in_scope: Optional[bool] = None
    authorization_basis: Optional[str] = None


class ServiceCreate(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: str = Field(default="https", pattern="^(https?|tcp)$")
    path: Optional[str] = Field(default=None, max_length=512)
    product: Optional[str] = Field(default=None, max_length=120)
    version: Optional[str] = Field(default=None, max_length=80)
    banner: Optional[str] = None
    source: str = Field(default="manual", max_length=24)
    confidence: str = Field(default="heuristic", pattern="^(exact|heuristic)$")


class DependencyItem(BaseModel):
    ecosystem: str = Field(min_length=1, max_length=32)
    package: str = Field(min_length=1, max_length=200)
    version: Optional[str] = Field(default=None, max_length=80)
    direct: bool = True


class DependencyImport(BaseModel):
    packages: list[DependencyItem] = Field(default_factory=list, max_length=20_000)
    scan_id: Optional[uuid.UUID] = None


class ProbeRequest(BaseModel):
    asset_ids: Optional[list[uuid.UUID]] = Field(
        default=None, description="Limit to these assets. Omit for the whole inventory."
    )
    rescan: bool = Field(
        default=False,
        description=(
            "Re-probe assets that already have a fingerprint. Without this, only assets "
            "the inventory knows nothing about are probed."
        ),
    )


class TechnologyCreate(BaseModel):
    product: str = Field(min_length=1, max_length=120)
    version: Optional[str] = Field(default=None, max_length=80)
    category: str = Field(default="other")
    confidence: str = Field(default="exact", pattern="^(exact|heuristic)$")


class SweepRequest(BaseModel):
    asset_ids: Optional[list[uuid.UUID]] = Field(
        default=None, description="Limit the sweep to these assets. Omit for the whole inventory."
    )
    cve_ids: Optional[list[str]] = Field(
        default=None, description="CVEs to apply. Omit to apply the whole local corpus."
    )
    verify: bool = False
    max_verifications: int = Field(default=25, ge=0, le=200)


class CveCheckRequest(BaseModel):
    cve_ids: Optional[list[str]] = Field(
        default=None,
        description="CVEs to check. Omit to check the whole local corpus.",
    )
    asset_ids: Optional[list[uuid.UUID]] = Field(
        default=None, description="Limit to these assets. Omit for the whole inventory."
    )
    verify: bool = Field(
        default=False,
        description=(
            "Let the model design and run read-only detection checks for the candidates "
            "that a version alone could not settle."
        ),
    )
    scan: bool = Field(
        default=True,
        description=(
            "Fingerprint assets that have no recorded product or version before matching "
            "(read-only HTTP probes and service banners on the asset's own hosts)."
        ),
    )
    max_verifications: int = Field(default=25, ge=0, le=200)


def _asset_dict(asset: am.Asset) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "name": asset.name,
        "kind": asset.kind,
        "description": asset.description,
        "owner": asset.owner,
        "environment": asset.environment,
        "in_scope": asset.in_scope,
        "authorization_basis": asset.authorization_basis,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
    }


def _service_dict(service_row: am.AssetService) -> dict[str, Any]:
    return {
        "id": str(service_row.id),
        "host": service_row.host,
        "port": service_row.port,
        "protocol": service_row.protocol,
        "path": service_row.path,
        "product": service_row.product,
        "version": service_row.version,
        "banner": service_row.banner,
        "source": service_row.source,
        "confidence": service_row.confidence,
        "last_seen": service_row.last_seen.isoformat() if service_row.last_seen else None,
    }


# ── Assets ──────────────────────────────────────────────────────────────────


@router.get("")
async def list_assets(user=Depends(current_active_user)) -> dict[str, Any]:
    assets = await service.list_assets(user.tenant_id)
    counts: dict[str, dict[str, int]] = {}
    for asset in assets:
        try:
            counts[str(asset.id)] = {
                "services": len(await service.list_services(user.tenant_id, asset.id)),
                "dependencies": len(await service.list_dependencies(user.tenant_id, asset.id)),
                "technologies": len(await service.list_technologies(user.tenant_id, asset.id)),
            }
        except service.AssetNotFound:
            counts[str(asset.id)] = {"services": 0, "dependencies": 0}
    return {
        "items": [
            {**_asset_dict(asset), **counts.get(str(asset.id), {})} for asset in assets
        ],
        "corpus": await service.corpus_stats(),
    }


@router.post("", status_code=201)
async def create_asset(body: AssetCreate, user=Depends(current_active_user)) -> dict[str, Any]:
    try:
        asset = await service.create_asset(
            tenant_id=user.tenant_id,
            name=body.name,
            kind=body.kind,
            description=body.description,
            owner=body.owner,
            environment=body.environment,
            in_scope=body.in_scope,
            authorization_basis=body.authorization_basis,
            created_by=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # An asset named after a host is an asset you can scan. Registering the host now
    # means a CVE check has somewhere to look instead of reporting "nothing found".
    from app.assets.discovery import looks_like_host

    if looks_like_host(body.name):
        try:
            await service.add_service(
                user.tenant_id,
                asset.id,
                host=body.name.strip(),
                source="inventory",
                confidence="heuristic",
            )
        except Exception:  # noqa: BLE001 — never fail asset creation for this
            logger.warning("could not register host for asset %s", asset.id, exc_info=True)
    return _asset_dict(asset)


@router.get("/{asset_id}")
async def get_asset(asset_id: uuid.UUID, user=Depends(current_active_user)) -> dict[str, Any]:
    try:
        asset = await service.get_asset(user.tenant_id, asset_id)
        services = await service.list_services(user.tenant_id, asset_id)
        dependencies = await service.list_dependencies(user.tenant_id, asset_id)
        technologies = await service.list_technologies(user.tenant_id, asset_id)
    except service.AssetNotFound as exc:
        raise HTTPException(status_code=404, detail="asset not found") from exc
    return {
        **_asset_dict(asset),
        "services": [_service_dict(row) for row in services],
        "technologies": [
            {
                "id": str(row.id),
                "product": row.product,
                "version": row.version,
                "category": row.category,
                "source": row.source,
                "confidence": row.confidence,
            }
            for row in technologies
        ],
        "dependencies": [
            {
                "id": str(row.id),
                "ecosystem": row.ecosystem,
                "package": row.package,
                "version": row.version,
                "direct": row.direct,
                "source": row.source,
            }
            for row in dependencies
        ],
    }


@router.patch("/{asset_id}")
async def update_asset(
    asset_id: uuid.UUID, body: AssetUpdate, user=Depends(current_active_user)
) -> dict[str, Any]:
    try:
        asset = await service.update_asset(
            user.tenant_id, asset_id, **body.model_dump(exclude_unset=True)
        )
    except service.AssetNotFound as exc:
        raise HTTPException(status_code=404, detail="asset not found") from exc
    return _asset_dict(asset)


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: uuid.UUID, user=Depends(current_active_user)) -> None:
    try:
        await service.delete_asset(user.tenant_id, asset_id)
    except service.AssetNotFound as exc:
        raise HTTPException(status_code=404, detail="asset not found") from exc


@router.post("/{asset_id}/services", status_code=201)
async def add_service(
    asset_id: uuid.UUID, body: ServiceCreate, user=Depends(current_active_user)
) -> dict[str, Any]:
    try:
        row = await service.add_service(
            user.tenant_id,
            asset_id,
            host=body.host,
            port=body.port,
            protocol=body.protocol,
            path=body.path,
            product=body.product,
            version=body.version,
            banner=body.banner,
            source=body.source,
            confidence=body.confidence,
        )
    except service.AssetNotFound as exc:
        raise HTTPException(status_code=404, detail="asset not found") from exc
    return _service_dict(row)


@router.post("/probe")
async def probe(body: ProbeRequest, user=Depends(current_active_user)) -> dict[str, Any]:
    """Scan the inventory and store what each asset is (technology, version)."""
    return await service.probe_inventory(
        tenant_id=user.tenant_id, asset_ids=body.asset_ids, rescan=body.rescan
    )


@router.post("/{asset_id}/technologies", status_code=201)
async def add_technology(
    asset_id: uuid.UUID, body: TechnologyCreate, user=Depends(current_active_user)
) -> dict[str, Any]:
    try:
        row = await service.add_technology(
            user.tenant_id,
            asset_id,
            product=body.product,
            version=body.version,
            category=body.category,
            source="manual",
            confidence=body.confidence,
        )
    except service.AssetNotFound as exc:
        raise HTTPException(status_code=404, detail="asset not found") from exc
    return {
        "id": str(row.id),
        "product": row.product,
        "version": row.version,
        "category": row.category,
        "source": row.source,
        "confidence": row.confidence,
    }


@router.post("/sweep")
async def sweep(body: SweepRequest, user=Depends(current_active_user)) -> dict[str, Any]:
    """Refresh the inventory's fingerprints, then apply a CVE list to it.

    Authorisation comes from the inventory: every swept asset is in scope by virtue
    of having been added, and its recorded hosts are the only ones contacted.
    """
    from app.assets import sweep as sweep_mod

    return await sweep_mod.run_sweep(
        tenant_id=user.tenant_id,
        asset_ids=body.asset_ids,
        cve_ids=body.cve_ids,
        verify=body.verify,
        max_verifications=body.max_verifications,
    )


@router.post("/{asset_id}/dependencies", status_code=201)
async def import_dependencies(
    asset_id: uuid.UUID, body: DependencyImport, user=Depends(current_active_user)
) -> dict[str, Any]:
    try:
        stored = await service.add_dependencies(
            user.tenant_id,
            asset_id,
            [item.model_dump() for item in body.packages],
            source="scan" if body.scan_id else "manual",
            scan_id=body.scan_id,
        )
    except service.AssetNotFound as exc:
        raise HTTPException(status_code=404, detail="asset not found") from exc
    return {"stored": stored}


# ── CVE corpus and applicability ─────────────────────────────────────────────


cve_router = APIRouter(prefix="/cve", tags=["Assets"])


@cve_router.get("/corpus")
async def corpus(user=Depends(current_active_user)) -> dict[str, Any]:
    return await service.corpus_stats()


@cve_router.post("/import")
async def import_corpus(
    kind: str = Query(description="nvd, osv or kev"),
    file: UploadFile = File(...),
    user=Depends(current_active_user),
) -> dict[str, Any]:
    """Import an offline feed file (NVD API page, OSV record/zip, CISA KEV)."""
    if kind not in ("nvd", "osv", "kev"):
        raise HTTPException(status_code=400, detail="kind must be nvd, osv or kev")
    from app.assets import loaders
    from app.infrastructure.database.database import AsyncSessionLocal

    suffix = ".zip" if (file.filename or "").endswith(".zip") else ".json"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        handle.write(await file.read())
        path = Path(handle.name)
    try:
        async with AsyncSessionLocal() as db:
            result = await loaders.import_feed(db, path, kind=kind)
    except Exception as exc:  # noqa: BLE001 — a bad feed is a 400, not a 500
        logger.warning("CVE import failed for %s: %s", file.filename, exc)
        raise HTTPException(status_code=400, detail=f"could not import feed: {exc}") from exc
    finally:
        path.unlink(missing_ok=True)
    return result


@cve_router.post("/check")
async def check_cves(
    body: CveCheckRequest, user=Depends(current_active_user)
) -> dict[str, Any]:
    """Match a CVE list against the inventory, optionally testing the candidates."""
    return await service.check_cves(
        tenant_id=user.tenant_id,
        cve_ids=body.cve_ids,
        asset_ids=body.asset_ids,
        verify=body.verify,
        scan=body.scan,
        max_verifications=body.max_verifications,
    )


@cve_router.get("/verdicts")
async def list_verdicts(
    asset_id: Optional[uuid.UUID] = Query(default=None),
    cve_id: Optional[str] = Query(default=None),
    verdict: Optional[str] = Query(default=None),
    user=Depends(current_active_user),
) -> dict[str, Any]:
    items = await service.list_verdicts(
        tenant_id=user.tenant_id, asset_id=asset_id, cve_id=cve_id, verdict=verdict
    )
    return {"items": items, "total": len(items)}


@cve_router.post("/verdicts/{verdict_id}/verify")
async def verify_verdict(
    verdict_id: uuid.UUID, user=Depends(current_active_user)
) -> dict[str, Any]:
    """Design a detection check for one candidate, run it, and record the verdict."""
    from app.assets import verification

    outcome = await verification.verify_verdict(verdict_id)
    if "error" in outcome:
        raise HTTPException(status_code=400, detail=str(outcome["error"]))
    return outcome
