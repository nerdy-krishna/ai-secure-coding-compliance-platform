"""CVE research, before anything is tested.

An operator picking a CVE should see what it *is* before committing time to it: what the
vulnerability does, which versions are affected, whether an exploit is known, and what
check would actually run against their assets. That is the pause between "check these
CVEs" and "test them".

The research is stored on the CVE (`cve_checks.research`), so it survives the page and can
be read again without paying for it twice.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from sqlalchemy import select

from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


def _exploit_references(record: am.CveRecord) -> list[dict[str, Any]]:
    """Reference links tagged as exploits, which is what "is there a PoC" means here."""
    found: list[dict[str, Any]] = []
    for reference in record.references or []:
        tags = [str(tag).lower() for tag in reference.get("tags") or []]
        if any("exploit" in tag or "proof" in tag for tag in tags):
            found.append({"url": reference.get("url"), "tags": tags})
    return found


async def _store(cve_id: str, research: dict[str, Any], template: Optional[str]) -> None:
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    async with AsyncSessionLocal() as db:
        statement = pg_insert(am.CveCheck).values(
            cve_id=cve_id, template=template, research=research, source="research"
        )
        statement = statement.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={"research": statement.excluded.research},
        )
        await db.execute(statement)
        await db.commit()


async def research_cve(
    cve_id: str, *, design_check: bool = True, actor_user_id: Optional[int] = None
) -> dict[str, Any]:
    """Everything an operator needs to decide whether to test this CVE."""
    from app.assets import enrichment
    from app.pentest.engine import resolve_default_llm_config_id
    from app.infrastructure.llm_client import get_llm_client

    key = cve_id.strip().upper()
    llm_config_id = await resolve_default_llm_config_id()
    llm = await get_llm_client(llm_config_id) if llm_config_id else None

    lookup = await enrichment.ensure_cve(key, llm=llm)
    if not lookup.get("present"):
        return {
            "cve_id": key,
            "error": lookup.get("reason") or "the CVE could not be found in any source",
        }

    async with AsyncSessionLocal() as db:
        record = await db.get(am.CveRecord, key)
        ranges = list(
            await db.scalars(select(am.CveAffected).where(am.CveAffected.cve_id == key))
        )
        # the check row is keyed by id, with cve_id unique
        stored = await db.scalar(select(am.CveCheck).where(am.CveCheck.cve_id == key))
    if record is None:
        return {"cve_id": key, "error": "the CVE record disappeared during research"}

    products = sorted({row.product for row in ranges if row.product})
    packages = sorted(
        {f"{row.ecosystem}/{row.package}" for row in ranges if row.package}
    )
    summary: dict[str, Any] = {
        "cve_id": key,
        "source": record.source,
        "description": record.description,
        "severity": record.severity,
        "cvss_score": record.cvss_score,
        "cvss_vector": record.cvss_vector,
        "cwe": record.cwe,
        "kev": record.kev,
        "published": record.published.isoformat() if record.published else None,
        "affected_products": products,
        "affected_packages": packages,
        "references": (record.references or [])[:12],
        # "Is there something to run" is a different question from "is it exploitable",
        # and both matter before you spend an afternoon on it.
        "exploit_references": _exploit_references(record),
        "research": (stored.research if stored is not None else None),
        "template": (stored.template if stored is not None and stored.template else None),
        "template_present": bool(stored is not None and stored.template),
        "ranges_known": bool(ranges),
    }

    def _looks_like_error(text: str | None) -> bool:
        lowered = (text or "").lower()
        return any(
            marker in lowered
            for marker in ("status_code:", "invalid_request_error", "authentication",
                           "api key", "rate limit", "timeout")
        )

    if not summary["research"] and llm is not None:
        from app.assets import verification

        researched = await verification.research_cve(
            llm, cve=record, ranges=ranges, actor_user_id=actor_user_id
        )
        if _looks_like_error(researched.mechanism):
            # The model could not be reached; say so instead of dressing the error up as
            # an explanation of the vulnerability.
            summary["research_error"] = researched.mechanism
            summary["research"] = None
        else:
            summary["research"] = researched.model_dump()
        summary["template"] = summary["template"] or None

    if design_check and not summary["template_present"] and llm is not None and ranges:
        from app.assets import verification

        generated = await verification.design_template(
            llm,
            cve=record,
            ranges=ranges,
            research=(
                verification.CveResearch(**summary["research"])
                if summary["research"]
                else None
            ),
            asset=None,  # no asset matched yet: the check is designed for the CVE
            actor_user_id=actor_user_id,
        )
        if generated:
            summary["template"] = generated
            summary["template_present"] = True

    await _store(key, summary["research"] or {}, summary["template"])
    return summary


async def browse(
    *,
    query: Optional[str] = None,
    severity: Optional[str] = None,
    kev_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """The corpus, searchable, so an operator can pick a CVE instead of typing an id."""
    from sqlalchemy import func, or_

    async with AsyncSessionLocal() as db:
        statement = select(am.CveRecord)
        if query:
            pattern = f"%{query.strip()}%"
            statement = statement.where(
                or_(am.CveRecord.id.ilike(pattern), am.CveRecord.description.ilike(pattern))
            )
        if severity:
            statement = statement.where(am.CveRecord.severity == severity.lower())
        if kev_only:
            statement = statement.where(am.CveRecord.kev.is_(True))
        total = await db.scalar(
            select(func.count()).select_from(statement.subquery())
        )
        rows = list(
            await db.scalars(
                statement.order_by(
                    am.CveRecord.kev.desc(),
                    am.CveRecord.cvss_score.desc().nullslast(),
                    am.CveRecord.id,
                )
                .limit(limit)
                .offset(offset)
            )
        )
    return {
        "total": int(total or 0),
        "items": [
            {
                "cve_id": row.id,
                "description": (row.description or "")[:300],
                "severity": row.severity,
                "cvss_score": row.cvss_score,
                "kev": row.kev,
                "published": row.published.isoformat() if row.published else None,
            }
            for row in rows
        ],
    }
