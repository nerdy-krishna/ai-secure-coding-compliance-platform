"""Asset inventory and CVE applicability: the operations behind the API.

The inventory is the authorisation boundary: an asset in scope is an asset whose
hosts may be fingerprinted, scanned and probed. That is why every sweep records the
basis it acted on (`assets.authorization_basis`) rather than an implicit "the
operator clicked go".
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

import sqlalchemy as sa
from sqlalchemy import delete, func, select

from app.assets import matcher
from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class AssetNotFound(LookupError):
    pass


# ── Assets ──────────────────────────────────────────────────────────────────


async def create_asset(
    *,
    tenant_id: uuid.UUID,
    name: str,
    kind: str = am.ASSET_WEB_APP,
    description: Optional[str] = None,
    owner: Optional[str] = None,
    environment: Optional[str] = None,
    in_scope: bool = True,
    authorization_basis: Optional[str] = None,
    created_by: Optional[int] = None,
) -> am.Asset:
    if kind not in am.ASSET_KINDS:
        raise ValueError(f"kind must be one of {', '.join(am.ASSET_KINDS)}")
    async with AsyncSessionLocal() as db:
        asset = am.Asset(
            tenant_id=tenant_id,
            name=name.strip()[:200],
            kind=kind,
            description=description,
            owner=owner,
            environment=environment,
            in_scope=in_scope,
            # Adding an asset is the authorisation; record who said so and when, so
            # a later sweep can explain why a host was in scope.
            authorization_basis=authorization_basis or "added to the asset inventory",
            created_by=created_by,
        )
        db.add(asset)
        await db.commit()
        await db.refresh(asset)
        return asset


async def list_assets(tenant_id: uuid.UUID) -> list[am.Asset]:
    async with AsyncSessionLocal() as db:
        rows = await db.scalars(
            select(am.Asset).where(am.Asset.tenant_id == tenant_id).order_by(am.Asset.name)
        )
        return list(rows)


async def get_asset(tenant_id: uuid.UUID, asset_id: uuid.UUID) -> am.Asset:
    async with AsyncSessionLocal() as db:
        asset = await db.get(am.Asset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        raise AssetNotFound(str(asset_id))
    return asset


async def update_asset(
    tenant_id: uuid.UUID, asset_id: uuid.UUID, **fields: Any
) -> am.Asset:
    allowed = {
        "name",
        "kind",
        "description",
        "owner",
        "environment",
        "in_scope",
        "authorization_basis",
    }
    async with AsyncSessionLocal() as db:
        asset = await db.get(am.Asset, asset_id)
        if asset is None or asset.tenant_id != tenant_id:
            raise AssetNotFound(str(asset_id))
        for key, value in fields.items():
            if key in allowed and value is not None:
                setattr(asset, key, value)
        await db.commit()
        await db.refresh(asset)
        return asset


async def delete_asset(tenant_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    async with AsyncSessionLocal() as db:
        asset = await db.get(am.Asset, asset_id)
        if asset is None or asset.tenant_id != tenant_id:
            raise AssetNotFound(str(asset_id))
        await db.delete(asset)
        await db.commit()


# ── Services and dependencies ────────────────────────────────────────────────


async def add_service(
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    *,
    host: str,
    port: Optional[int] = None,
    protocol: str = "https",
    path: Optional[str] = None,
    product: Optional[str] = None,
    version: Optional[str] = None,
    banner: Optional[str] = None,
    source: str = "manual",
    confidence: str = "heuristic",
    run_id: Optional[uuid.UUID] = None,
) -> am.AssetService:
    await get_asset(tenant_id, asset_id)
    async with AsyncSessionLocal() as db:
        existing = await db.scalar(
            select(am.AssetService).where(
                am.AssetService.asset_id == asset_id,
                am.AssetService.host == host,
                am.AssetService.port.is_(port) if port is None else am.AssetService.port == port,
                am.AssetService.path.is_(path) if path is None else am.AssetService.path == path,
            )
        )
        if existing is not None:
            # A later observation of the same endpoint is fresher, not a new row.
            existing.product = product or existing.product
            existing.version = version or existing.version
            existing.banner = banner or existing.banner
            existing.source = source
            existing.confidence = confidence
            existing.protocol = protocol
            existing.last_seen = func.now()
            await db.commit()
            await db.refresh(existing)
            return existing
        service = am.AssetService(
            asset_id=asset_id,
            host=host,
            port=port,
            protocol=protocol,
            path=path,
            product=product,
            version=version,
            banner=banner,
            source=source,
            confidence=confidence,
            run_id=run_id,
        )
        db.add(service)
        await db.commit()
        await db.refresh(service)
        return service


async def list_services(tenant_id: uuid.UUID, asset_id: uuid.UUID) -> list[am.AssetService]:
    await get_asset(tenant_id, asset_id)
    async with AsyncSessionLocal() as db:
        rows = await db.scalars(
            select(am.AssetService)
            .where(am.AssetService.asset_id == asset_id)
            .order_by(am.AssetService.host)
        )
        return list(rows)


async def add_dependencies(
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    packages: list[dict[str, Any]],
    *,
    source: str = "manual",
    scan_id: Optional[uuid.UUID] = None,
) -> int:
    """Upsert package versions. These are the *declared* half of the matcher."""
    await get_asset(tenant_id, asset_id)
    stored = 0
    async with AsyncSessionLocal() as db:
        for package in packages:
            ecosystem = str(package.get("ecosystem") or "").strip()
            name = str(package.get("package") or package.get("name") or "").strip()
            if not ecosystem or not name:
                continue
            version = str(package.get("version") or "").strip() or None
            existing = await db.scalar(
                select(am.AssetDependency).where(
                    am.AssetDependency.asset_id == asset_id,
                    am.AssetDependency.ecosystem == ecosystem,
                    am.AssetDependency.package == name,
                    am.AssetDependency.version.is_(version)
                    if version is None
                    else am.AssetDependency.version == version,
                )
            )
            if existing is None:
                db.add(
                    am.AssetDependency(
                        asset_id=asset_id,
                        ecosystem=ecosystem,
                        package=name,
                        version=version,
                        direct=bool(package.get("direct", True)),
                        scan_id=scan_id,
                        source=source,
                    )
                )
                stored += 1
        await db.commit()
    return stored


async def list_dependencies(
    tenant_id: uuid.UUID, asset_id: uuid.UUID
) -> list[am.AssetDependency]:
    await get_asset(tenant_id, asset_id)
    async with AsyncSessionLocal() as db:
        rows = await db.scalars(
            select(am.AssetDependency)
            .where(am.AssetDependency.asset_id == asset_id)
            .order_by(am.AssetDependency.ecosystem, am.AssetDependency.package)
        )
        return list(rows)


# ── CVE applicability ────────────────────────────────────────────────────────


async def _assets_needing_discovery(
    db, *, tenant_id: uuid.UUID, asset_ids: Optional[list[uuid.UUID]]
) -> list[uuid.UUID]:
    """Assets with no product or version recorded anywhere.

    These are the ones a check cannot say anything useful about yet, so they are the
    ones worth touching the network for. An asset that is already fingerprinted is
    matched from the inventory and not re-probed on every check.
    """
    query = select(am.Asset.id).where(
        am.Asset.tenant_id == tenant_id, am.Asset.in_scope.is_(True)
    )
    if asset_ids:
        query = query.where(am.Asset.id.in_(asset_ids))
    rows = list(await db.scalars(query))
    unknown: list[uuid.UUID] = []
    for asset_id in rows:
        known = await db.scalar(
            select(func.count())
            .select_from(am.AssetService)
            .where(
                am.AssetService.asset_id == asset_id,
                sa.or_(
                    am.AssetService.product.isnot(None),
                    am.AssetService.version.isnot(None),
                ),
            )
        )
        if not known:
            unknown.append(asset_id)
    return unknown


async def check_cves(
    *,
    tenant_id: uuid.UUID,
    cve_ids: Optional[list[str]] = None,
    asset_ids: Optional[list[uuid.UUID]] = None,
    verify: bool = False,
    scan: bool = True,
    max_verifications: int = 25,
) -> dict[str, Any]:
    """Fingerprint what is unknown, match the CVE list, and optionally test the rest.

    `scan` is what turns "nothing found" into an answer: an asset with no recorded
    product and version is probed first (read-only HTTP and banner checks against its
    own hosts), so the matcher has something to work with.
    """
    discovery: dict[str, Any] = {}
    if scan:
        from app.assets import discovery as discovery_mod

        async with AsyncSessionLocal() as db:
            unknown = await _assets_needing_discovery(
                db, tenant_id=tenant_id, asset_ids=asset_ids
            )
        if unknown:
            discovery = await discovery_mod.discover_assets(unknown)

    async with AsyncSessionLocal() as db:
        findings = await matcher.match_cves_for_tenant(
            db, tenant_id=tenant_id, cve_ids=cve_ids, asset_ids=asset_ids
        )
        stored = await matcher.store_findings(db, tenant_id=tenant_id, findings=findings)

        counts = {am.APPLICABLE: 0, am.NOT_APPLICABLE: 0, am.UNDETERMINED: 0}
        for finding in findings:
            counts[finding.verdict] = counts.get(finding.verdict, 0) + 1

        result: dict[str, Any] = {
            "scanned": bool(discovery),
            **(discovery or {}),
            "matched": stored,
            "applicable": counts[am.APPLICABLE],
            "undetermined": counts[am.UNDETERMINED],
            "not_applicable": counts[am.NOT_APPLICABLE],
            "verified": 0,
            "verification_errors": 0,
        }
        if not verify or not stored:
            return result

        # Only version-only observations are worth a test: a declared match is
        # already exact, and a probe costs a request against a live asset.
        candidates = list(
            await db.scalars(
                select(am.AssetCveVerdict)
                .where(
                    am.AssetCveVerdict.tenant_id == tenant_id,
                    am.AssetCveVerdict.basis == am.BASIS_OBSERVED,
                    am.AssetCveVerdict.verdict == am.UNDETERMINED,
                )
                .order_by(am.AssetCveVerdict.checked_at.desc())
                .limit(max_verifications)
            )
        )

    from app.assets import verification

    for candidate in candidates:
        outcome = await verification.verify_verdict(candidate.id)
        if "error" in outcome:
            result["verification_errors"] += 1
        else:
            result["verified"] += 1
    return result


async def list_verdicts(
    *,
    tenant_id: uuid.UUID,
    asset_id: Optional[uuid.UUID] = None,
    cve_id: Optional[str] = None,
    verdict: Optional[str] = None,
) -> list[dict[str, Any]]:
    async with AsyncSessionLocal() as db:
        query = (
            select(am.AssetCveVerdict, am.CveRecord, am.Asset)
            .join(am.CveRecord, am.CveRecord.id == am.AssetCveVerdict.cve_id)
            .join(am.Asset, am.Asset.id == am.AssetCveVerdict.asset_id)
            .where(am.AssetCveVerdict.tenant_id == tenant_id)
        )
        if asset_id:
            query = query.where(am.AssetCveVerdict.asset_id == asset_id)
        if cve_id:
            query = query.where(am.AssetCveVerdict.cve_id == cve_id)
        if verdict:
            query = query.where(am.AssetCveVerdict.verdict == verdict)
        rows = (await db.execute(query)).all()

    return [
        {
            "id": str(row.AssetCveVerdict.id),
            "asset_id": str(row.AssetCveVerdict.asset_id),
            "asset_name": row.Asset.name,
            "cve_id": row.AssetCveVerdict.cve_id,
            "title": (row.CveRecord.description or "")[:200],
            "cvss_score": row.CveRecord.cvss_score,
            "severity": row.CveRecord.severity,
            "kev": row.CveRecord.kev,
            "verdict": row.AssetCveVerdict.verdict,
            "confidence": row.AssetCveVerdict.confidence,
            "basis": row.AssetCveVerdict.basis,
            "reason": row.AssetCveVerdict.reason,
            "evidence": row.AssetCveVerdict.evidence,
            "probe": row.AssetCveVerdict.probe,
            "checked_at": row.AssetCveVerdict.checked_at.isoformat()
            if row.AssetCveVerdict.checked_at
            else None,
        }
        for row in rows
    ]


async def corpus_stats() -> dict[str, int]:
    async with AsyncSessionLocal() as db:
        total = await db.scalar(select(func.count()).select_from(am.CveRecord))
        kev = await db.scalar(
            select(func.count()).select_from(am.CveRecord).where(am.CveRecord.kev.is_(True))
        )
        ranges = await db.scalar(select(func.count()).select_from(am.CveAffected))
        deps = await db.scalar(select(func.count()).select_from(am.AssetDependency))
        services = await db.scalar(select(func.count()).select_from(am.AssetService))
    return {
        "cves": int(total or 0),
        "kev": int(kev or 0),
        "affected_ranges": int(ranges or 0),
        "dependencies": int(deps or 0),
        "services": int(services or 0),
    }


async def purge_verdicts(tenant_id: uuid.UUID, asset_id: Optional[uuid.UUID] = None) -> int:
    async with AsyncSessionLocal() as db:
        query = delete(am.AssetCveVerdict).where(am.AssetCveVerdict.tenant_id == tenant_id)
        if asset_id:
            query = query.where(am.AssetCveVerdict.asset_id == asset_id)
        result = await db.execute(query)
        await db.commit()
        return int(result.rowcount or 0)
