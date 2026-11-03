"""Deterministic CVE matching against the inventory.

Two sources of truth feed one verdict table:

- **declared** — the version a dependency actually resolved to (from a code scan's
  SBOM). Exact, high confidence, and the reason dependency CVEs and runtime CVEs
  share a table instead of living in two half-truths.
- **observed** — a product/version taken from a banner. Heuristic: banners lie,
  backports are unversioned, and a vendor may have patched without bumping. A match
  here is a *candidate*, and the verdict says so (`undetermined`, medium) until a
  probe or the LLM verification settles it.

Nothing in this module guesses. An unknown version yields no verdict rather than a
comfortable "not affected".
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets import models as am
from app.assets.versions import in_range, pairs, product_matches

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A candidate verdict, before it is stored."""

    asset_id: uuid.UUID
    cve_id: str
    verdict: str
    confidence: str
    basis: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


async def load_cve(db: AsyncSession, cve_id: str) -> Optional[am.CveRecord]:
    return await db.get(am.CveRecord, cve_id)


async def affected_ranges(db: AsyncSession, cve_id: str) -> list[am.CveAffected]:
    rows = await db.scalars(select(am.CveAffected).where(am.CveAffected.cve_id == cve_id))
    return list(rows)


def _declared_match(
    cve_id: str,
    dependency: am.AssetDependency,
    ranges: list[am.CveAffected],
) -> Optional[Finding]:
    package = (dependency.package or "").strip().lower()
    ecosystem = (dependency.ecosystem or "").strip().lower()
    for row in ranges:
        if row.kind != "ecosystem" or not row.package:
            continue
        if row.ecosystem and ecosystem and row.ecosystem.lower() != ecosystem:
            continue
        if row.package.lower() != package:
            continue
        if in_range(
            dependency.version,
            start_incl=row.version_start_incl,
            start_excl=row.version_start_excl,
            end_incl=row.version_end_incl,
            end_excl=row.version_end_excl,
            exact=row.exact_versions,
        ):
            return Finding(
                asset_id=dependency.asset_id,
                cve_id=cve_id,
                verdict=am.APPLICABLE,
                confidence="high",
                basis=am.BASIS_DECLARED,
                reason=(
                    f"{ecosystem}/{dependency.package} {dependency.version} is inside the "
                    f"affected range of {cve_id}."
                ),
                evidence={
                    "package": dependency.package,
                    "version": dependency.version,
                    "ecosystem": ecosystem,
                    "range": {
                        "start_incl": row.version_start_incl,
                        "start_excl": row.version_start_excl,
                        "end_incl": row.version_end_incl,
                        "end_excl": row.version_end_excl,
                        "exact": row.exact_versions,
                    },
                    "source": dependency.source,
                    "scan_id": str(dependency.scan_id) if dependency.scan_id else None,
                },
            )
    return None


def _observed_match(
    cve_id: str,
    service: am.AssetService,
    ranges: list[am.CveAffected],
) -> Optional[Finding]:
    # A banner can name several products (proxy + origin). Consider every pair, so
    # the version tested is the one belonging to the product the CVE is about.
    candidates = pairs(" ".join(filter(None, [service.product, service.banner])))
    if service.version:
        candidates.append((service.product or "", service.version))
    for row in ranges:
        if row.kind != "cpe" or not row.product:
            continue
        matching = [
            (name, version)
            for name, version in candidates
            if product_matches(row.product, name)
        ]
        if not matching and service.product and product_matches(row.product, service.product):
            matching = [(service.product, service.version or "")]
        if not matching:
            continue
        named_product = matching[0][0] or service.product
        known_version = next((version for _name, version in matching if version), None)
        if known_version and not in_range(
            known_version,
            start_incl=row.version_start_incl,
            start_excl=row.version_start_excl,
            end_incl=row.version_end_incl,
            end_excl=row.version_end_excl,
            exact=row.exact_versions,
        ):
            continue
        if not known_version:
            # The product is right and the version is missing: a probe can settle it.
            # Saying nothing here is what made an un-fingerprinted IP look clean.
            return Finding(
                asset_id=service.asset_id,
                cve_id=cve_id,
                verdict=am.UNDETERMINED,
                confidence="low",
                basis=am.BASIS_OBSERVED,
                reason=(
                    f"{service.host}{':' + str(service.port) if service.port else ''} reports "
                    f"{named_product}, which {cve_id} affects, but no version — obtain the "
                    f"version to decide."
                ),
                evidence={
                    "host": service.host,
                    "port": service.port,
                    "product": named_product,
                    "version": None,
                    "banner": (service.banner or "")[:500],
                    "range": {
                        "start_incl": row.version_start_incl,
                        "start_excl": row.version_start_excl,
                        "end_incl": row.version_end_incl,
                        "end_excl": row.version_end_excl,
                        "exact": row.exact_versions,
                    },
                    "needs_version": True,
                },
            )
        # A banner match is a hypothesis: the version may be backported-patched, or
        # the banner may be a deliberate lie. Only a test settles it.
        return Finding(
            asset_id=service.asset_id,
            cve_id=cve_id,
            verdict=am.UNDETERMINED,
            confidence="medium",
            basis=am.BASIS_OBSERVED,
            reason=(
                f"{service.host}{':' + str(service.port) if service.port else ''} reports "
                f"{service.product or 'an unidentified product'} {service.version}, which is "
                f"inside the affected range of {cve_id}. Version alone cannot confirm it."
            ),
            evidence={
                "host": service.host,
                "port": service.port,
                "path": service.path,
                "product": named_product,
                "version": known_version,
                "banner": (service.banner or "")[:500],
                "service_confidence": service.confidence,
                "range": {
                    "start_incl": row.version_start_incl,
                    "start_excl": row.version_start_excl,
                    "end_incl": row.version_end_incl,
                    "end_excl": row.version_end_excl,
                    "exact": row.exact_versions,
                },
            },
        )
    return None


def _technology_match(
    cve_id: str,
    technology: am.AssetTechnology,
    ranges: list[am.CveAffected],
) -> Optional[Finding]:
    for row in ranges:
        if row.kind != "cpe" or not row.product:
            continue
        if not product_matches(row.product, technology.product):
            continue
        version_known = bool((technology.version or "").strip())
        if version_known and not in_range(
            technology.version,
            start_incl=row.version_start_incl,
            start_excl=row.version_start_excl,
            end_incl=row.version_end_incl,
            end_excl=row.version_end_excl,
            exact=row.exact_versions,
        ):
            continue
        return Finding(
            asset_id=technology.asset_id,
            cve_id=cve_id,
            verdict=am.UNDETERMINED,
            confidence="medium" if version_known else "low",
            basis=am.BASIS_OBSERVED,
            reason=(
                f"the asset records {technology.product} "
                f"{technology.version or '(version unknown)'}, which {cve_id} affects"
                + ("" if version_known else "; obtain the version to decide")
            ),
            evidence={
                "product": technology.product,
                "version": technology.version,
                "category": technology.category,
                "source": technology.source,
                "technology_confidence": technology.confidence,
                "needs_version": not version_known,
                "range": {
                    "start_incl": row.version_start_incl,
                    "start_excl": row.version_start_excl,
                    "end_incl": row.version_end_incl,
                    "end_excl": row.version_end_excl,
                    "exact": row.exact_versions,
                },
            },
        )
    return None


async def match_cve_for_asset(
    db: AsyncSession, *, asset_id: uuid.UUID, cve_id: str
) -> list[Finding]:
    """Every candidate verdict for one (asset, CVE) pair."""
    ranges = await affected_ranges(db, cve_id)
    if not ranges:
        return []

    findings: list[Finding] = []

    dependencies = await db.scalars(
        select(am.AssetDependency).where(am.AssetDependency.asset_id == asset_id)
    )
    for dependency in dependencies:
        hit = _declared_match(cve_id, dependency, ranges)
        if hit is not None:
            findings.append(hit)

    services = await db.scalars(
        select(am.AssetService).where(am.AssetService.asset_id == asset_id)
    )
    for service in services:
        hit = _observed_match(cve_id, service, ranges)
        if hit is not None:
            findings.append(hit)

    technologies = await db.scalars(
        select(am.AssetTechnology).where(am.AssetTechnology.asset_id == asset_id)
    )
    for technology in technologies:
        hit = _technology_match(cve_id, technology, ranges)
        if hit is not None:
            findings.append(hit)

    return findings


async def match_cves_for_tenant(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    cve_ids: Optional[list[str]] = None,
    asset_ids: Optional[list[uuid.UUID]] = None,
) -> list[Finding]:
    """Match a CVE list (or the whole corpus) across the tenant's assets.

    `cve_ids=None` means "everything in the corpus", which is what a broad sweep
    asks for. The query is bounded by the inventory, so the cost tracks assets, not
    the size of the CVE feed.
    """
    asset_query = select(am.Asset.id).where(
        am.Asset.tenant_id == tenant_id, am.Asset.in_scope.is_(True)
    )
    if asset_ids:
        asset_query = asset_query.where(am.Asset.id.in_(asset_ids))
    asset_rows = list(await db.scalars(asset_query))
    if not asset_rows:
        return []

    if cve_ids:
        cves = [c for c in cve_ids if c]
    else:
        cves = list(await db.scalars(select(am.CveRecord.id)))

    findings: list[Finding] = []
    for cve_id in cves:
        for asset_id in asset_rows:
            findings.extend(await match_cve_for_asset(db, asset_id=asset_id, cve_id=cve_id))
    return findings


_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
_VERDICT_RANK = {am.NOT_APPLICABLE: 0, am.UNDETERMINED: 1, am.APPLICABLE: 2}


def _better(left: Finding, right: Finding) -> Finding:
    """Which of two candidate verdicts for the same pair is worth keeping.

    The same (asset, CVE, basis) can now be reached twice — a product seen on an
    endpoint and recorded again as a technology, for instance. Keeping the weaker one
    would throw away the version that was actually observed.
    """
    left_version = bool((left.evidence or {}).get("version"))
    right_version = bool((right.evidence or {}).get("version"))
    if left_version != right_version:
        return left if left_version else right
    left_score = (_VERDICT_RANK.get(left.verdict, 0), _CONFIDENCE_RANK.get(left.confidence, 0))
    right_score = (_VERDICT_RANK.get(right.verdict, 0), _CONFIDENCE_RANK.get(right.confidence, 0))
    return left if left_score >= right_score else right


async def store_findings(
    db: AsyncSession, *, tenant_id: uuid.UUID, findings: list[Finding]
) -> list[Finding]:
    """Upsert candidate verdicts, keyed by (asset, cve, basis)."""
    unique: dict[tuple[uuid.UUID, str, str], Finding] = {}
    for finding in findings:
        key = (finding.asset_id, finding.cve_id, finding.basis)
        existing = unique.get(key)
        unique[key] = finding if existing is None else _better(existing, finding)
    findings = list(unique.values())

    stored = 0
    for finding in findings:
        existing = await db.scalar(
            select(am.AssetCveVerdict).where(
                am.AssetCveVerdict.asset_id == finding.asset_id,
                am.AssetCveVerdict.cve_id == finding.cve_id,
                am.AssetCveVerdict.basis == finding.basis,
            )
        )
        if existing is None:
            db.add(
                am.AssetCveVerdict(
                    tenant_id=tenant_id,
                    asset_id=finding.asset_id,
                    cve_id=finding.cve_id,
                    verdict=finding.verdict,
                    confidence=finding.confidence,
                    basis=finding.basis,
                    reason=finding.reason,
                    evidence=finding.evidence,
                )
            )
        else:
            existing.verdict = finding.verdict
            existing.confidence = finding.confidence
            existing.reason = finding.reason
            existing.evidence = finding.evidence
        stored += 1
    await db.commit()
    return findings


def needs_verification(verdict: am.AssetCveVerdict) -> bool:
    """Only an observed, version-only match is worth spending a test on."""
    return verdict.basis == am.BASIS_OBSERVED and verdict.verdict == am.UNDETERMINED
