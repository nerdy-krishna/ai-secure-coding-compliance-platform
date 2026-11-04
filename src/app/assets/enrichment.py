"""Getting a CVE that is not in the local corpus.

The corpus is loaded from feed files, so a CVE published after the last import — or a
typo'd id, or a fresh advisory — used to stop an operator dead: "not in the local
corpus" and nothing else. That is a dead end where the useful behaviour is obvious:
go and get it, then carry on.

Three sources, tried in order, each one recorded so the operator knows how much to
trust the record:

1. **NVD** — authoritative affected ranges (CPE), CVSS, references. Requested live for
   the one id; no key needed (the API is rate-limited without one).
2. **OSV** — package-level advisories, which is what dependency matching needs.
3. **The model** — if neither is reachable (air-gapped, egress blocked), the CVE is
   reconstructed from the model's knowledge and stored with `source="model"`. That is
   clearly marked as unverified rather than passed off as authoritative, because a
   hallucinated version range would produce confident nonsense downstream.

Nothing is imported wholesale: enrichment is per id, on demand, and the result is
written into the same corpus tables the matcher and the verification already use.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx
from pydantic import BaseModel, Field

from app.assets import loaders
from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/vulns"
FETCH_TIMEOUT = 20.0


class ModelCveRecord(BaseModel):
    """A CVE reconstructed by the model when no feed is reachable."""

    description: str = Field(description="What the vulnerability is, in two or three sentences.")
    affected_products: list[str] = Field(
        default_factory=list,
        description=(
            "Products named by the advisory, e.g. ['nginx']. Only what you actually know; "
            "an invented product produces a false match."
        ),
    )
    version_start_incl: Optional[str] = Field(default=None)
    version_end_excl: Optional[str] = Field(default=None)
    version_end_incl: Optional[str] = Field(default=None)
    cvss_score: Optional[float] = Field(default=None)
    severity: Optional[str] = Field(default=None, description="critical|high|medium|low|none")
    cwe: Optional[str] = Field(default=None)
    references: list[str] = Field(default_factory=list)
    confidence: str = Field(
        default="low",
        description="high only when the advisory details are known precisely, otherwise low",
    )


async def fetch_nvd(cve_id: str) -> Optional[tuple[am.CveRecord, list[am.CveAffected]]]:
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            response = await client.get(NVD_API, params={"cveId": cve_id})
        if response.status_code != 200:
            logger.info("NVD returned %s for %s", response.status_code, cve_id)
            return None
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 — offline is a normal condition here
        logger.info("NVD unreachable for %s: %s", cve_id, exc)
        return None
    records = loaders.parse_nvd(payload)
    for record, affected in records:
        if record.id.upper() == cve_id.upper():
            return record, affected
    return None


async def fetch_osv(cve_id: str) -> Optional[tuple[am.CveRecord, list[am.CveAffected]]]:
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            response = await client.get(f"{OSV_API}/{cve_id}")
        if response.status_code != 200:
            return None
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        logger.info("OSV unreachable for %s: %s", cve_id, exc)
        return None
    records = loaders.parse_osv(payload)
    return records[0] if records else None


async def _describe_with_model(cve_id: str, llm: Any) -> Optional[tuple[am.CveRecord, list[am.CveAffected]]]:
    """Last resort: ask the model, and mark the record as unverified."""
    try:
        result = await llm.generate_structured_output(
            prompt=(
                f"Describe {cve_id} as a security advisory does: what the vulnerability is, "
                "which products it affects, the affected version range, the CVSS score and "
                "severity, the CWE, and any reference URLs you know. Only state what you "
                "actually know — if you are unsure of the range, leave it empty rather than "
                "guessing, because a wrong range produces a wrong answer downstream."
            ),
            response_model=ModelCveRecord,
            system_prompt=(
                "You are reconstructing a public CVE record from your own knowledge because "
                "no advisory feed is reachable. Accuracy matters more than completeness."
            ),
            usage_context=_usage_context(cve_id),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("model could not describe %s: %s", cve_id, exc)
        return None
    parsed = result.parsed_output
    if parsed is None or not parsed.description.strip():
        return None

    record = am.CveRecord(
        id=cve_id.upper(),
        description=parsed.description.strip()[:8000],
        cvss_score=parsed.cvss_score,
        severity=(parsed.severity or "").lower() or None,
        cwe=parsed.cwe,
        references=[{"url": url, "tags": ["model"]} for url in parsed.references[:10]],
        source="model",
    )
    affected: list[am.CveAffected] = []
    for product in parsed.affected_products[:5]:
        affected.append(
            am.CveAffected(
                cve_id=cve_id.upper(),
                kind="cpe",
                product=str(product)[:200],
                version_start_incl=parsed.version_start_incl,
                version_end_excl=parsed.version_end_excl,
                version_end_incl=parsed.version_end_incl,
            )
        )
    return record, affected


def _usage_context(cve_id: str):
    import uuid

    from app.infrastructure.llm_client import LLMUsageContext

    return LLMUsageContext(
        operation_kind="cve",
        operation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"sccap:cve:{cve_id}")),
        stage="cve.enrich",
        agent_name="cve-enricher",
        idempotency_key=str(uuid.uuid5(uuid.NAMESPACE_URL, f"sccap:enrich:{cve_id}")),
    )


async def ensure_cve(
    cve_id: str, *, llm: Any = None, allow_model: bool = True
) -> dict[str, Any]:
    """Make sure a CVE is in the corpus, fetching or reconstructing it if needed.

    Returns `{cve_id, present, source, fetched, reason}`. `present` is what the caller
    acts on; `source` says how much the record can be trusted.
    """
    key = cve_id.strip().upper()
    async with AsyncSessionLocal() as db:
        existing = await db.get(am.CveRecord, key)
        if existing is not None:
            return {"cve_id": key, "present": True, "source": existing.source, "fetched": False}

    for source, fetch in (("nvd", fetch_nvd), ("osv", fetch_osv)):
        outcome = await fetch(key)
        if outcome is None:
            continue
        record, affected = outcome
        async with AsyncSessionLocal() as db:
            await loaders.upsert_records(db, [(record, affected)])
        logger.info("enriched %s from %s (%d range(s))", key, source, len(affected))
        return {"cve_id": key, "present": True, "source": source, "fetched": True}

    if allow_model and llm is not None:
        outcome = await _describe_with_model(key, llm)
        if outcome is not None:
            record, affected = outcome
            async with AsyncSessionLocal() as db:
                await loaders.upsert_records(db, [(record, affected)])
            logger.warning("reconstructed %s from model knowledge (unverified)", key)
            return {
                "cve_id": key,
                "present": True,
                "source": "model",
                "fetched": True,
                "unverified": True,
            }

    return {
        "cve_id": key,
        "present": False,
        "source": None,
        "fetched": False,
        "reason": (
            "not in the local corpus, and no advisory feed or model was reachable — "
            "import an NVD or OSV feed, or check egress from the app container"
        ),
    }


async def ensure_cves(
    cve_ids: list[str], *, llm: Any = None, allow_model: bool = True
) -> dict[str, Any]:
    """Enrich a list; returns what was fetched, what is still missing, and how."""
    fetched: list[dict[str, Any]] = []
    missing: list[str] = []
    unverified: list[str] = []
    for cve_id in cve_ids:
        outcome = await ensure_cve(cve_id, llm=llm, allow_model=allow_model)
        if not outcome.get("present"):
            missing.append(outcome["cve_id"])
            continue
        if outcome.get("fetched"):
            fetched.append({"cve_id": outcome["cve_id"], "source": outcome["source"]})
        if outcome.get("unverified"):
            unverified.append(outcome["cve_id"])
    return {"fetched": fetched, "missing": missing, "unverified": unverified}
