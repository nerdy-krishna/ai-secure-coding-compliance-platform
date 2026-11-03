"""Loading the CVE corpus from NVD, OSV and CISA KEV.

Both feeds are loaded from files: an NVD API page (2.0 JSON), an OSV record or an
OSV zip export, and the KEV catalogue. Offline-first is deliberate — a verdict that
depends on a live rate-limited API cannot be reproduced, audited or run air-gapped,
and this platform already treats reproducibility as a requirement.

The parsers are intentionally tolerant: feeds evolve, and a field that moved should
cost a warning, not the whole import.
"""

from __future__ import annotations

import json
import logging
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets import models as am

logger = logging.getLogger(__name__)


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    text = value.replace("Z", "+00:00")
    for candidate in (text, text[:19]):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _severity_from_score(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _cpe_parts(criteria: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """`cpe:2.3:a:vendor:product:version:…` → (vendor, product, version)."""
    parts = (criteria or "").split(":")
    if len(parts) < 6:
        return None, None, None
    vendor, product, version = parts[3], parts[4], parts[5]
    clean = lambda value: None if value in ("*", "-", "") else value  # noqa: E731
    return clean(vendor), clean(product), clean(version)


def _nvd_ranges(cve: dict[str, Any]) -> list[am.CveAffected]:
    ranges: list[am.CveAffected] = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") is False:
                    continue
                vendor, product, version = _cpe_parts(match.get("criteria") or "")
                if not product:
                    continue
                row = am.CveAffected(
                    cve_id=cve["id"],
                    kind="cpe",
                    vendor=vendor,
                    product=product,
                    version_start_incl=match.get("versionStartIncluding"),
                    version_start_excl=match.get("versionStartExcluding"),
                    version_end_incl=match.get("versionEndIncluding"),
                    version_end_excl=match.get("versionEndExcluding"),
                )
                if version and not any(
                    [
                        row.version_start_incl,
                        row.version_start_excl,
                        row.version_end_incl,
                        row.version_end_excl,
                    ]
                ):
                    row.exact_versions = [version]
                ranges.append(row)
    return ranges


def _nvd_metrics(cve: dict[str, Any]) -> tuple[Optional[float], Optional[str], Optional[str], Optional[str]]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(key)
        if not metrics:
            continue
        data = metrics[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = metrics[0].get("baseSeverity") or data.get("baseSeverity")
        return score, (severity.lower() if isinstance(severity, str) else None), data.get("vectorString"), None
    return None, None, None, None


def _nvd_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Advisory, patch and exploit links, with their tags.

    These are what a researcher reads next after the description: the vendor advisory
    says which versions are fixed, an exploit link says how it is triggered.
    """
    references: list[dict[str, Any]] = []
    for reference in cve.get("references") or []:
        url = reference.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        references.append(
            {
                "url": url[:500],
                "source": (reference.get("source") or "")[:120] or None,
                "tags": [str(tag)[:40] for tag in (reference.get("tags") or [])][:8],
            }
        )
    return references[:40]


def _nvd_cwe(cve: dict[str, Any]) -> Optional[str]:
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = description.get("value")
            if isinstance(value, str) and value.startswith("CWE-"):
                return value
    return None


def parse_nvd(payload: dict[str, Any]) -> list[tuple[am.CveRecord, list[am.CveAffected]]]:
    """Parse an NVD 2.0 API page (`{"vulnerabilities": [...]}`)."""
    records: list[tuple[am.CveRecord, list[am.CveAffected]]] = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        description = ""
        for entry in cve.get("descriptions") or []:
            if entry.get("lang") == "en":
                description = entry.get("value") or ""
                break
        score, severity, vector, _ = _nvd_metrics(cve)
        record = am.CveRecord(
            id=cve_id,
            description=description or None,
            cvss_score=score,
            cvss_vector=vector,
            severity=severity or _severity_from_score(score),
            cwe=_nvd_cwe(cve),
            published=_parse_dt(cve.get("published")),
            modified=_parse_dt(cve.get("lastModified")),
            references=_nvd_references(cve) or None,
            source="nvd",
        )
        records.append((record, _nvd_ranges(cve)))
    return records


def _osv_ids(record: dict[str, Any]) -> list[str]:
    """Prefer a CVE id; fall back to the OSV/GHSA id so package advisories land too."""
    ids = [record.get("id") or ""]
    ids.extend(record.get("aliases") or [])
    cves = [value for value in ids if isinstance(value, str) and value.startswith("CVE-")]
    if cves:
        return cves
    return [ids[0]] if ids and ids[0] else []


def _osv_ranges(osv_id: str, record: dict[str, Any]) -> list[am.CveAffected]:
    rows: list[am.CveAffected] = []
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not name:
            continue
        versions = affected.get("versions") or []
        for entry in affected.get("ranges") or []:
            if entry.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced: Optional[str] = None
            for event in entry.get("events") or []:
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    rows.append(
                        am.CveAffected(
                            cve_id=osv_id,
                            kind="ecosystem",
                            ecosystem=ecosystem,
                            package=name,
                            version_start_incl=None if introduced in (None, "0") else introduced,
                            version_end_excl=event["fixed"],
                        )
                    )
                    introduced = None
                elif "last_affected" in event:
                    rows.append(
                        am.CveAffected(
                            cve_id=osv_id,
                            kind="ecosystem",
                            ecosystem=ecosystem,
                            package=name,
                            version_start_incl=None if introduced in (None, "0") else introduced,
                            version_end_incl=event["last_affected"],
                        )
                    )
                    introduced = None
            if introduced not in (None, "0"):
                # An open-ended range: introduced, never fixed.
                rows.append(
                    am.CveAffected(
                        cve_id=osv_id,
                        kind="ecosystem",
                        ecosystem=ecosystem,
                        package=name,
                        version_start_incl=introduced,
                    )
                )
        if versions and not any(row.package == name for row in rows):
            rows.append(
                am.CveAffected(
                    cve_id=osv_id,
                    kind="ecosystem",
                    ecosystem=ecosystem,
                    package=name,
                    exact_versions=[
                        version for version in versions[:200] if isinstance(version, str)
                    ],
                )
            )
    return rows


def parse_osv(payload: dict[str, Any]) -> list[tuple[am.CveRecord, list[am.CveAffected]]]:
    """Parse one OSV record (or a list of them)."""
    records: list[tuple[am.CveRecord, list[am.CveAffected]]] = []
    items = payload if isinstance(payload, list) else [payload]
    for item in items:
        if not isinstance(item, dict):
            continue
        ids = _osv_ids(item)
        if not ids:
            continue
        cve_id = ids[0]
        severity = None
        score = None
        for entry in item.get("severity") or []:
            value = entry.get("score") or ""
            # CVSS vector strings carry no score; keep the vector, derive later.
            if isinstance(value, str) and value.startswith("CVSS:"):
                severity = severity or None
        database_specific = item.get("database_specific") or {}
        if isinstance(database_specific.get("severity"), str):
            severity = database_specific["severity"].lower()
        references = [
            {
                "url": str(entry.get("url"))[:500],
                "source": str(entry.get("type") or "").lower()[:120] or None,
                "tags": [str(entry.get("type") or "advisory").lower()][:8],
            }
            for entry in (item.get("references") or [])
            if isinstance(entry, dict) and str(entry.get("url", "")).startswith("http")
        ]
        record = am.CveRecord(
            id=cve_id,
            description=(item.get("details") or item.get("summary") or None),
            cvss_score=score,
            severity=severity or _severity_from_score(score),
            published=_parse_dt(item.get("published")),
            modified=_parse_dt(item.get("modified")),
            references=references[:40] or None,
            source="osv",
        )
        records.append((record, _osv_ranges(cve_id, item)))
    return records


def parse_kev(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """CISA KEV: `{"vulnerabilities": [{"cveID", "dueDate"}]}`."""
    rows = []
    for item in payload.get("vulnerabilities") or []:
        cve_id = item.get("cveID")
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            rows.append({"cve_id": cve_id, "due": _parse_dt(item.get("dueDate"))})
    return rows


async def upsert_records(
    db: AsyncSession, records: Iterable[tuple[am.CveRecord, list[am.CveAffected]]]
) -> dict[str, int]:
    """Insert or update CVEs and replace their affected ranges.

    Two passes on purpose: the parent records are flushed before child ranges are
    added. `CveAffected` carries a plain foreign key with no ORM relationship, so
    SQLAlchemy cannot order the inserts by dependency and would otherwise write a
    range before the CVE it belongs to.
    """
    batch = list(records)
    created = updated = ranges = 0
    pending_ranges: dict[str, list[am.CveAffected]] = {}

    for record, affected in batch:
        existing = await db.get(am.CveRecord, record.id)
        if existing is None:
            db.add(record)
            created += 1
        else:
            # Never blank out curated fields with an empty feed value.
            existing.description = record.description or existing.description
            existing.cvss_score = record.cvss_score or existing.cvss_score
            existing.cvss_vector = record.cvss_vector or existing.cvss_vector
            existing.severity = record.severity or existing.severity
            existing.cwe = record.cwe or existing.cwe
            existing.published = record.published or existing.published
            existing.modified = record.modified or existing.modified
            existing.references = record.references or existing.references
            updated += 1
        if affected:
            pending_ranges[record.id] = affected

    await db.flush()

    for cve_id, affected in pending_ranges.items():
        for row in list(
            await db.scalars(select(am.CveAffected).where(am.CveAffected.cve_id == cve_id))
        ):
            await db.delete(row)
        await db.flush()
        for row in affected:
            db.add(row)
            ranges += 1

    await db.commit()
    return {"created": created, "updated": updated, "ranges": ranges}


async def apply_kev(db: AsyncSession, rows: list[dict[str, Any]]) -> int:
    marked = 0
    for row in rows:
        record = await db.get(am.CveRecord, row["cve_id"])
        if record is None:
            continue
        record.kev = True
        record.kev_due = row.get("due")
        marked += 1
    await db.commit()
    return marked


def read_feed(path: Path) -> list[dict[str, Any]]:
    """Read a JSON feed, a JSON array, or an OSV zip export."""
    if path.suffix == ".zip":
        payloads: list[dict[str, Any]] = []
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    data = json.loads(archive.read(name))
                except json.JSONDecodeError:
                    logger.warning("skipping unreadable OSV entry %s", name)
                    continue
                payloads.extend(data if isinstance(data, list) else [data])
        return payloads
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else [data]


async def import_feed(db: AsyncSession, path: Path, *, kind: str) -> dict[str, int]:
    """Import one feed file. `kind` is nvd, osv or kev."""
    if kind == "kev":
        marked = 0
        for payload in read_feed(path):
            marked += await apply_kev(db, parse_kev(payload))
        return {"kev_marked": marked}

    records: list[tuple[am.CveRecord, list[am.CveAffected]]] = []
    for payload in read_feed(path):
        if kind == "nvd":
            records.extend(parse_nvd(payload))
        else:
            records.extend(parse_osv(payload))
    result = await upsert_records(db, records)
    return result
