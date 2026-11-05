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


async def add_technology(
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    *,
    product: str,
    version: Optional[str] = None,
    category: str = am.TECH_OTHER,
    source: str = "manual",
    confidence: str = "heuristic",
    evidence: Optional[dict[str, Any]] = None,
) -> am.AssetTechnology:
    """Record a product an asset runs, with or without a network endpoint.

    A managed database, a firewall image or a Kubernetes version has no URL to fetch
    but is exactly what a CVE list needs to be checked against.
    """
    await get_asset(tenant_id, asset_id)
    if category not in am.TECH_CATEGORIES:
        category = am.TECH_OTHER
    async with AsyncSessionLocal() as db:
        existing = await db.scalar(
            select(am.AssetTechnology).where(
                am.AssetTechnology.asset_id == asset_id,
                am.AssetTechnology.product == product[:120],
                am.AssetTechnology.version.is_(version)
                if version is None
                else am.AssetTechnology.version == version,
            )
        )
        if existing is not None:
            existing.category = category
            existing.source = source
            existing.confidence = confidence
            if evidence:
                existing.evidence = evidence
            existing.updated_at = func.now()
            await db.commit()
            await db.refresh(existing)
            return existing
        technology = am.AssetTechnology(
            asset_id=asset_id,
            product=product.strip()[:120],
            version=(version or "").strip()[:80] or None,
            category=category,
            source=source,
            confidence=confidence,
            evidence=evidence,
        )
        db.add(technology)
        await db.commit()
        await db.refresh(technology)
        return technology


async def list_technologies(
    tenant_id: uuid.UUID, asset_id: uuid.UUID
) -> list[am.AssetTechnology]:
    await get_asset(tenant_id, asset_id)
    async with AsyncSessionLocal() as db:
        rows = await db.scalars(
            select(am.AssetTechnology)
            .where(am.AssetTechnology.asset_id == asset_id)
            .order_by(am.AssetTechnology.product)
        )
        return list(rows)


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


async def probe_inventory(
    *, tenant_id: uuid.UUID, asset_ids: Optional[list[uuid.UUID]] = None, rescan: bool = False
) -> dict[str, Any]:
    """Probe assets and store what they are.

    `rescan=False` probes only the assets the inventory knows nothing about, which is
    what a check needs. `rescan=True` re-probes everything, which is what an operator
    asks for after a change and what keeps the stored technology current.
    """
    from app.assets import discovery as discovery_mod

    async with AsyncSessionLocal() as db:
        if rescan:
            query = select(am.Asset.id).where(
                am.Asset.tenant_id == tenant_id, am.Asset.in_scope.is_(True)
            )
            if asset_ids:
                query = query.where(am.Asset.id.in_(asset_ids))
            targets = list(await db.scalars(query))
        else:
            targets = await _assets_needing_discovery(
                db, tenant_id=tenant_id, asset_ids=asset_ids
            )
    from app.assets import events as events_mod

    if not targets:
        return {
            "assets_probed": 0,
            "endpoints_probed": 0,
            "fingerprints_found": 0,
            "products": [],
            "note": "every in-scope asset already has a fingerprint; use rescan to refresh",
        }

    async with AsyncSessionLocal() as db:
        asset_names = {
            str(asset_id): name
            for asset_id, name in (
                await db.execute(
                    select(am.Asset.id, am.Asset.name).where(am.Asset.tenant_id == tenant_id)
                )
            ).all()
        }
    # If the pentest engine is alive, queue the probe for it: that container carries
    # nmap, whatweb and nuclei, which is a far better answer than a Python GET.
    from app.pentest import inventory_probe

    if await inventory_probe.engine_alive():
        async with AsyncSessionLocal() as db:
            for asset_id in targets:
                rows = list(
                    await db.scalars(
                        select(am.AssetService).where(am.AssetService.asset_id == asset_id)
                    )
                )
                asset = await db.get(am.Asset, asset_id)
                host = next(
                    (row.host for row in rows if row.host), None
                ) or (asset.name if asset is not None else None)
                if host:
                    db.add(
                        am.AssetProbeJob(
                            tenant_id=tenant_id,
                            asset_id=asset_id,
                            host=host,
                            tools=["nmap", "whatweb", "nuclei"],
                        )
                    )
            await db.commit()
        await events_mod.emit(
            tenant_id,
            f"probe queued for the pentest engine: {len(targets)} asset(s) "
            "(nmap -sV, whatweb, nuclei with the bundled templates)",
            kind="start",
        )
        return {
            "assets_probed": 0,
            "endpoints_probed": 0,
            "fingerprints_found": 0,
            "products": [],
            "queued": len(targets),
            "engine": True,
            "note": "queued for the pentest engine — progress appears in this console",
        }

    probe_id = uuid.uuid4()
    await events_mod.emit(
        tenant_id,
        f"probe started: {len(targets)} asset(s) — "
        + ", ".join(asset_names.get(str(a), str(a)) for a in targets[:5])
        + (" …" if len(targets) > 5 else ""),
        kind="start",
        check_id=probe_id,
    )
    # Without events here, clicking "Probe inventory" produced no console output at
    # all — the operator could not tell whether it ran.
    outcome = await discovery_mod.discover_assets(
        targets,
        labels=asset_names,
        on_event=lambda message, level="info", payload=None: events_mod.emit(
            tenant_id,
            message,
            level=level,
            kind="fingerprint",
            payload=payload,
            check_id=probe_id,
        ),
    )
    await events_mod.emit(
        tenant_id,
        f"probe finished: {outcome.get('endpoints_probed', 0)} endpoint(s), "
        f"{outcome.get('fingerprints_found', 0)} fingerprint(s)"
        + (
            " — " + ", ".join(outcome["products"])
            if outcome.get("products")
            else " — no product identified"
        ),
        level="success" if outcome.get("fingerprints_found") else "warning",
        kind="done",
        payload=outcome,
        check_id=probe_id,
    )
    return outcome


async def _explain_no_candidates(
    tenant_id: uuid.UUID, *, cve_ids: list[str] | None, check_id: uuid.UUID
) -> None:
    """Say *why* nothing matched: which product was expected, which is reported.

    "0 candidates" on its own is indistinguishable from a broken check.
    """
    from app.assets import events as events_mod

    if not cve_ids:
        return
    async with AsyncSessionLocal() as db:
        wanted: set[str] = set()
        for cve_id in cve_ids:
            for row in await db.scalars(
                select(am.CveAffected).where(am.CveAffected.cve_id == cve_id)
            ):
                if row.product:
                    wanted.add(row.product.lower())
        reported: set[str] = set()
        for service_row in await db.scalars(
            select(am.AssetService).where(am.AssetService.product.isnot(None))
        ):
            reported.add((service_row.product or "").lower())
        for tech in await db.scalars(
            select(am.AssetTechnology).where(am.AssetTechnology.product.isnot(None))
        ):
            reported.add((tech.product or "").lower())
    if not wanted or (wanted & reported):
        return
    await events_mod.emit(
        tenant_id,
        "no candidate: this CVE affects "
        + ", ".join(sorted(wanted))
        + ", and the inventory reports "
        + (", ".join(sorted(reported)) if reported else "no product at all")
        + ". Record the technology (or open the port it runs on), then check again.",
        level="warning",
        kind="match",
        check_id=check_id,
    )


async def probe_status(tenant_id: uuid.UUID) -> dict[str, Any]:
    """Is a probe running right now, and how much is queued?

    The probe can take minutes; without this an operator has only the activity console to
    tell a slow probe from a dead button.
    """
    from app.pentest import inventory_probe

    async with AsyncSessionLocal() as db:
        queued = await db.scalar(
            select(func.count())
            .select_from(am.AssetProbeJob)
            .where(
                am.AssetProbeJob.tenant_id == tenant_id,
                am.AssetProbeJob.status == "queued",
            )
        )
        running = await db.scalar(
            select(func.count())
            .select_from(am.AssetProbeJob)
            .where(
                am.AssetProbeJob.tenant_id == tenant_id,
                am.AssetProbeJob.status == "running",
            )
        )
        current = await db.scalar(
            select(am.AssetProbeJob.host)
            .where(
                am.AssetProbeJob.tenant_id == tenant_id,
                am.AssetProbeJob.status == "running",
            )
            .limit(1)
        )
        last = await db.scalar(
            select(func.max(am.AssetEvent.created_at)).where(
                am.AssetEvent.tenant_id == tenant_id
            )
        )
    engine = await inventory_probe.engine_alive()
    return {
        "active": bool(queued or running) or not engine,
        "queued": int(queued or 0),
        "running": int(running or 0),
        "host": current,
        "engine": engine,
        "last_event_at": last.isoformat() if last else None,
    }


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
    from app.assets import events as events_mod

    check_id = uuid.uuid4()
    await events_mod.emit(
        tenant_id,
        f"check started: {len(cve_ids) if cve_ids else 'all corpus CVE(s)'}"
        + (f" across {len(asset_ids)} asset(s)" if asset_ids else " across the inventory"),
        kind="start",
        payload={"cve_count": len(cve_ids or []), "scan": scan, "verify": verify},
        check_id=check_id,
    )

    async with AsyncSessionLocal() as db:
        asset_names: dict[str, str] = {
            str(asset_id): name
            for asset_id, name in (
                await db.execute(
                    select(am.Asset.id, am.Asset.name).where(am.Asset.tenant_id == tenant_id)
                )
            ).all()
        }

    discovery: dict[str, Any] = {}
    if scan:
        from app.assets import discovery as discovery_mod

        async with AsyncSessionLocal() as db:
            unknown = await _assets_needing_discovery(
                db, tenant_id=tenant_id, asset_ids=asset_ids
            )
        if unknown:
            await events_mod.emit(
                tenant_id,
                "probing "
                + ", ".join(asset_names.get(str(a), str(a)) for a in unknown[:5])
                + (" …" if len(unknown) > 5 else "")
                + " (no recorded technology)",
                kind="discovery",
                check_id=check_id,
            )
            discovery = await discovery_mod.discover_assets(
                unknown,
                labels=asset_names,
                on_event=lambda message, level="info", payload=None: events_mod.emit(
                    tenant_id,
                    message,
                    level=level,
                    kind="fingerprint",
                    payload=payload,
                    check_id=check_id,
                ),
            )
            await events_mod.emit(
                tenant_id,
                f"probing done: {discovery.get('endpoints_probed', 0)} endpoint(s), "
                f"{discovery.get('fingerprints_found', 0)} fingerprint(s)",
                level="success" if discovery.get("fingerprints_found") else "warning",
                kind="fingerprint",
                payload=discovery,
                check_id=check_id,
            )

    # A CVE that is not in the corpus is fetched, not refused: the corpus is a cache
    # of public data, and an operator pasting an id expects it to be looked up. This
    # has to happen *before* matching, or a freshly fetched CVE has no ranges in the
    # match set and the check reports zero candidates.
    unknown_cves: list[str] = []
    enrichment: dict[str, Any] = {}
    if cve_ids:
        from app.assets import enrichment as enrichment_mod

        llm = None
        if verify:
            try:
                from app.infrastructure.llm_client import get_llm_client
                from app.pentest.engine import resolve_default_llm_config_id

                config_id = await resolve_default_llm_config_id()
                if config_id is not None:
                    llm = await get_llm_client(config_id)
            except Exception:  # noqa: BLE001 — enrichment must not break a check
                logger.warning("no LLM available to describe a missing CVE", exc_info=True)

        enrichment = await enrichment_mod.ensure_cves(cve_ids, llm=llm)
        unknown_cves = enrichment.get("missing", [])
        for item in enrichment.get("fetched", []):
            unverified = item["cve_id"] in enrichment.get("unverified", [])
            await events_mod.emit(
                tenant_id,
                f"{item['cve_id']} was not in the corpus — fetched from {item['source']}"
                + (" (reconstructed by the model; treat as unverified)" if unverified else ""),
                level="warning" if unverified else "info",
                kind="enrich",
                check_id=check_id,
            )
            # Say what was fetched: an operator who cannot see the CVE has no way to
            # judge whether the check that follows is the right one.
            async with AsyncSessionLocal() as detail_db:
                record = await detail_db.get(am.CveRecord, item["cve_id"])
                ranges = list(
                    await detail_db.scalars(
                        select(am.CveAffected).where(
                            am.CveAffected.cve_id == item["cve_id"]
                        )
                    )
                )
                template = await detail_db.scalar(
                    select(am.CveCheck).where(am.CveCheck.cve_id == item["cve_id"])
                )
            if record is not None:
                products = sorted({row.product for row in ranges if row.product})
                await events_mod.emit(
                    tenant_id,
                    f"{item['cve_id']}: {record.severity or 'unrated'}"
                    + (f" · CVSS {record.cvss_score}" if record.cvss_score else "")
                    + f" · affects {', '.join(products) or 'an unidentified product'}"
                    + f" · {(record.description or '')[:160]}",
                    kind="enrich",
                    payload={
                        "description": record.description,
                        "products": products,
                        "ranges": [
                            {
                                "product": row.product,
                                "start_incl": row.version_start_incl,
                                "end_excl": row.version_end_excl,
                            }
                            for row in ranges
                        ],
                        "references": len(record.references or []),
                    },
                    check_id=check_id,
                )
                await events_mod.emit(
                    tenant_id,
                    (
                        f"{item['cve_id']}: a detection check is already stored (reused for every asset)"
                        if template is not None
                        else f"{item['cve_id']}: no detection check yet — one is written when an asset "
                        "reports the affected product and the candidate is tested"
                    ),
                    kind="template",
                    payload={"present": template is not None},
                    check_id=check_id,
                )
        for missing in unknown_cves:
            await events_mod.emit(
                tenant_id,
                f"{missing} could not be found in NVD, OSV or from the model",
                level="error",
                kind="enrich",
                check_id=check_id,
            )

    async with AsyncSessionLocal() as db:
        findings = await matcher.match_cves_for_tenant(
            db, tenant_id=tenant_id, cve_ids=cve_ids, asset_ids=asset_ids
        )
        stored_findings = await matcher.store_findings(
            db, tenant_id=tenant_id, findings=findings
        )
        stored = len(stored_findings)

        counts = {am.APPLICABLE: 0, am.NOT_APPLICABLE: 0, am.UNDETERMINED: 0}
        for finding in stored_findings:
            counts[finding.verdict] = counts.get(finding.verdict, 0) + 1
            await events_mod.emit(
                tenant_id,
                f"{finding.cve_id} → {asset_names.get(str(finding.asset_id), str(finding.asset_id))}: "
                f"{finding.verdict} ({finding.basis})",
                level="warning" if finding.verdict == am.UNDETERMINED else "info",
                kind="match",
                payload={"reason": finding.reason, "evidence": finding.evidence},
                check_id=check_id,
            )

        result: dict[str, Any] = {
            "scanned": bool(discovery),
            "unknown_cves": unknown_cves,
            "enriched": enrichment.get("fetched", []),
            "unverified_cves": enrichment.get("unverified", []),
            **(discovery or {}),
            "matched": stored,
            "applicable": counts[am.APPLICABLE],
            "undetermined": counts[am.UNDETERMINED],
            "not_applicable": counts[am.NOT_APPLICABLE],
            "verified": 0,
            "verification_errors": 0,
        }
        if not verify or not stored:
            if not result["matched"]:
                await _explain_no_candidates(tenant_id, cve_ids=cve_ids, check_id=check_id)
            await events_mod.emit(
                tenant_id,
                f"check finished: {result['matched']} candidate(s), {result['applicable']} applicable, "
                f"{result['undetermined']} needing a test",
                level="success" if result["matched"] else "warning",
                kind="done",
                payload={
                    "matched": result["matched"],
                    "applicable": result["applicable"],
                    "undetermined": result["undetermined"],
                },
                check_id=check_id,
            )
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
        await events_mod.emit(
            tenant_id,
            f"testing {candidate.cve_id} on {asset_names.get(str(candidate.asset_id), str(candidate.asset_id))}",
            kind="verify",
            check_id=check_id,
        )
        outcome = await verification.verify_verdict(candidate.id)
        if "error" in outcome:
            result["verification_errors"] += 1
            await events_mod.emit(
                tenant_id,
                f"verification failed for {candidate.cve_id}: {outcome['error']}",
                level="error",
                kind="verify",
                check_id=check_id,
            )
        else:
            result["verified"] += 1
            await events_mod.emit(
                tenant_id,
                f"{candidate.cve_id}: {outcome.get('verdict')} ({outcome.get('confidence')}) "
                f"after {outcome.get('checks', 0)} check(s)",
                level="success" if outcome.get("verdict") == am.APPLICABLE else "info",
                kind="verify",
                payload=outcome,
                check_id=check_id,
            )
    if not result["matched"]:
        await _explain_no_candidates(tenant_id, cve_ids=cve_ids, check_id=check_id)
    await events_mod.emit(
        tenant_id,
        f"check finished: {result['matched']} candidate(s), {result['applicable']} applicable, "
        f"{result['undetermined']} needing a test, {result['verified']} tested",
        level="success",
        kind="done",
        payload={
            "matched": result["matched"],
            "applicable": result["applicable"],
            "undetermined": result["undetermined"],
            "verified": result["verified"],
        },
        check_id=check_id,
    )
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
