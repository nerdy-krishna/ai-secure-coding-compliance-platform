"""LLM-assisted CVE applicability: design a check, run it, judge the result.

A version range answers "does this build claim to be affected". It does not answer
"is this asset affected": banners lie, distributions backport fixes without bumping
the version, and a vendor may ship a patched build under the same number. So a
candidate that the matcher could not settle is verified the way a human would:

1. **Design.** The model reads the CVE (description, affected range) and what the
   inventory knows about the asset, and designs a small set of *detection* checks —
   requests whose response would distinguish a vulnerable build from a patched one
   (a version endpoint, a header, a file that only exists in affected releases).
2. **Run.** The checks execute under a hard safety envelope (see `SAFE_METHODS`):
   read-only methods, no request body, only the asset's own hosts, a short timeout,
   one request per check.
3. **Judge.** The model sees the observations and must name the check that decided
   it. A verdict of `applicable` without a deciding observation is downgraded to
   `undetermined` — the feature's job is to be trusted, and an unearned verdict is
   worth less than an honest "cannot tell".

Destructive testing stays where it already lives (ADR-028, explicit operator
authorisation). This path never sends a payload that changes state.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Literal, Optional

import httpx
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.assets import checks
from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.llm_client import LLMClient, LLMUsageContext, get_llm_client

logger = logging.getLogger(__name__)

# The safety envelope. GET/HEAD/OPTIONS cannot create, update or delete anything on
# a target; anything else is destructive testing and has its own authorisation flow.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_CHECKS = 4
CHECK_TIMEOUT_SECONDS = 15.0
MAX_BODY_CHARS = 4000
MAX_REDIRECTS = 0


class CheckTemplateOut(BaseModel):
    """A Nuclei-compatible detection check for one CVE."""

    template: str = Field(
        description=(
            "A complete Nuclei-style YAML template. Detection only: GET/HEAD/OPTIONS, "
            "no request body, matchers limited to status, word, regex and size over "
            "header or body, {{BaseURL}} for the target. It must distinguish a "
            "vulnerable build from a patched one, and must not attempt exploitation."
        )
    )
    rationale: str = Field(
        default="",
        description="Why this check decides the question for this CVE.",
    )


class CveResearch(BaseModel):
    """What the vulnerability is and what would prove it, before any probe exists."""

    mechanism: str = Field(
        description=(
            "How the vulnerability works, in the terms of the affected product: which "
            "input reaches which code path, and under what preconditions it is exploitable."
        )
    )
    detection_signals: list[str] = Field(
        default_factory=list,
        description=(
            "Observable facts that distinguish a vulnerable build from a patched one — a "
            "version, a feature that only exists in affected releases, an endpoint whose "
            "behaviour changed, a header, a default credential."
        ),
    )
    patched_version: Optional[str] = Field(
        default=None,
        description="First version that is fixed, if the advisory says so.",
    )
    reference_insights: list[str] = Field(
        default_factory=list,
        description=(
            "What the advisories and exploit write-ups add beyond the description — "
            "affected configurations, prerequisites, or a known trigger pattern."
        ),
    )
    testability_note: str = Field(
        default="",
        description=(
            "Whether a read-only check can decide it, or whether confirming it would "
            "require sending an exploit payload (which this step must not do)."
        ),
    )


class ProbeCheck(BaseModel):
    method: Literal["GET", "HEAD", "OPTIONS"] = Field(
        default="GET", description="Read-only method. Use GET unless only headers matter."
    )
    url: str = Field(
        description=(
            "Absolute URL on one of the asset's hosts. Use the port and scheme you were "
            "given. Paths that disclose a build version are usually the most decisive."
        )
    )
    rationale: str = Field(description="Why this request distinguishes vulnerable from patched")
    decides: str = Field(
        description=(
            "The concrete observation that would settle applicability — e.g. 'the Server "
            "header reports 1.18.0, which is inside the affected range'."
        )
    )


class DetectionPlan(BaseModel):
    reasoning: str = Field(description="How you intend to tell an affected build from a patched one")
    non_destructive: bool = Field(
        default=True,
        description="True only if every check is read-only and cannot change target state",
    )
    checks: list[ProbeCheck] = Field(
        default_factory=list,
        description=f"At most {MAX_CHECKS} checks, each a single request",
    )


class VerdictDecision(BaseModel):
    verdict: Literal["applicable", "not_applicable", "undetermined"] = Field(
        description=(
            "applicable: an observation shows this build is vulnerable; not_applicable: the "
            "observation rules it out; undetermined: the checks did not distinguish the two"
        )
    )
    confidence: Literal["low", "medium", "high"] = Field(default="low")
    reason: str = Field(description="What the observations showed, and which check decided it")
    deciding_check: Optional[int] = Field(
        default=None,
        description=(
            "1-based index of the check whose observation decided the verdict, or null when "
            "nothing did. Required for 'applicable' and 'not_applicable'."
        ),
    )


def _usage_context(cve_id: str, stage: str, asset_id: Any = None) -> LLMUsageContext:
    # Usage attribution requires a UUID, and a CVE id is not one. A name-based UUID
    # keeps the attribution stable per CVE across runs.
    return LLMUsageContext(
        operation_kind="cve",
        asset_id=asset_id,
        operation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"sccap:cve:{cve_id}")),
        stage=stage,
        agent_name="cve-verifier",
        idempotency_key=str(uuid.uuid4()),
    )


def _render_asset(asset: am.Asset, services: list[am.AssetService]) -> str:
    lines = [
        f"Asset: {asset.name} ({asset.kind})",
        f"Owner: {asset.owner or 'unknown'} · environment: {asset.environment or 'unknown'}",
    ]
    for service in services:
        endpoint = f"{service.protocol}://{service.host}"
        if service.port and not (
            (service.protocol == "https" and service.port == 443)
            or (service.protocol == "http" and service.port == 80)
        ):
            endpoint += f":{service.port}"
        if service.path:
            endpoint += service.path
        lines.append(
            f"- {endpoint} reports product={service.product or '?'} "
            f"version={service.version or '?'} (source {service.source}, "
            f"confidence {service.confidence})"
        )
        if service.banner:
            lines.append(f"  banner: {service.banner[:300]}")
    return "\n".join(lines)


def _render_references(cve: am.CveRecord, limit: int = 12) -> str:
    references = cve.references or []
    if not references:
        return "No advisory or exploit references are stored for this CVE."
    lines = ["References (advisories, patches, exploit write-ups):"]
    for reference in references[:limit]:
        tags = ", ".join(reference.get("tags") or []) or "reference"
        lines.append(f"- [{tags}] {reference.get('url')}")
    return "\n".join(lines)


def _render_cve(cve: am.CveRecord, ranges: list[am.CveAffected]) -> str:
    lines = [
        f"CVE: {cve.id}",
        f"CVSS: {cve.cvss_score if cve.cvss_score is not None else 'n/a'} "
        f"({cve.severity or 'unrated'}) · CWE: {cve.cwe or 'n/a'} · "
        f"known exploited: {'yes' if cve.kev else 'no'}",
    ]
    if cve.description:
        lines.append(f"Description: {cve.description[:1500]}")
    for row in ranges:
        if row.kind == "cpe":
            bound = []
            if row.version_start_incl:
                bound.append(f">={row.version_start_incl}")
            if row.version_start_excl:
                bound.append(f">{row.version_start_excl}")
            if row.version_end_incl:
                bound.append(f"<={row.version_end_incl}")
            if row.version_end_excl:
                bound.append(f"<{row.version_end_excl}")
            if row.exact_versions:
                bound.append("one of " + ", ".join(row.exact_versions[:10]))
            lines.append(
                f"Affected product: {row.vendor or '?'}/{row.product or '?'} "
                f"versions {' '.join(bound) or '(all)'}"
            )
        else:
            bound = []
            if row.version_start_incl:
                bound.append(f">={row.version_start_incl}")
            if row.version_start_excl:
                bound.append(f">{row.version_start_excl}")
            if row.version_end_incl:
                bound.append(f"<={row.version_end_incl}")
            if row.version_end_excl:
                bound.append(f"<{row.version_end_excl}")
            if row.exact_versions:
                bound.append("one of " + ", ".join(row.exact_versions[:10]))
            lines.append(
                f"Affected package: {row.ecosystem or '?'}/{row.package or '?'} "
                f"versions {' '.join(bound) or '(all)'}"
            )
    return "\n".join(lines)


async def design_template(
    llm: LLMClient,
    *,
    cve: am.CveRecord,
    ranges: list[am.CveAffected],
    research: CveResearch | None,
    asset: am.Asset,
) -> Optional[str]:
    """Write the reusable check for this CVE, once.

    One template per CVE is the point: the same software is then tested identically on
    every asset, and the check can be read, exported and re-run by a human.
    """
    prompt = (
        f"{_render_cve(cve, ranges)}\n\n{_render_references(cve)}\n\n"
        f"{_render_research(research)}\n\n"
        f"Example of the shape expected:\n"
        "id: CVE-2021-23017-version\n"
        "info:\n"
        "  name: nginx resolver off-by-one (version check)\n"
        "  severity: high\n"
        "http:\n"
        "  - method: GET\n"
        "    path: [\"{{BaseURL}}/\"]\n"
        "    matchers-condition: and\n"
        "    matchers:\n"
        "      - type: word\n"
        "        part: header\n"
        "        words: [\"nginx\"]\n"
        "      - type: regex\n"
        "        part: header\n"
        "        regex: [\"nginx/1\\.1[0-9]\\.\"]\n\n"
        "Write the check for this CVE. Read-only requests only, no body, at most four "
        "requests, matchers over header or body. It must be specific to this "
        "vulnerability, not a generic fingerprint."
    )
    result = await llm.generate_structured_output(
        prompt=prompt,
        response_model=CheckTemplateOut,
        system_prompt=(
            "You write Nuclei-style detection templates for defensive verification. "
            "Detection only: never a request that changes state, never an exploit payload."
        ),
        usage_context=_usage_context(cve.id, "cve.template", asset.id),
    )
    parsed = result.parsed_output
    if parsed is None or not parsed.template.strip():
        return None
    try:
        checks.parse_template(parsed.template)
    except checks.TemplateInvalid as exc:
        logger.warning("model produced an unusable template for %s: %s", cve.id, exc)
        return None
    return parsed.template


async def research_cve(
    llm: LLMClient, *, cve: am.CveRecord, ranges: list[am.CveAffected], asset: am.Asset
) -> CveResearch:
    """Read the CVE and its references and say how it would be detected.

    Separate from designing the probe on purpose: understanding the vulnerability and
    choosing a request are different acts, and the first one is what makes the second
    specific to this CVE rather than generic version-checking.
    """
    prompt = (
        f"{_render_cve(cve, ranges)}\n\n{_render_references(cve)}\n\n"
        "Study this vulnerability as a researcher would. Explain the mechanism, then "
        "state the observable signals that separate a vulnerable build from a patched "
        "one, and what the references add. Say plainly whether a read-only check can "
        "decide it or whether proof would need an exploit payload."
    )
    result = await llm.generate_structured_output(
        prompt=prompt,
        response_model=CveResearch,
        system_prompt=(
            "You research CVEs for defensive verification. You read advisories and exploit "
            "write-ups and extract what is needed to tell a vulnerable system from a "
            "patched one, without attempting exploitation."
        ),
        usage_context=_usage_context(cve.id, "cve.research", asset.id),
    )
    return result.parsed_output or CveResearch(
        mechanism=result.error or "research unavailable",
        detection_signals=[],
        testability_note="",
    )


def _render_research(research: CveResearch | None) -> str:
    if research is None:
        return ""
    lines = [f"Vulnerability mechanism: {research.mechanism}"]
    if research.detection_signals:
        lines.append("Detection signals:")
        lines.extend(f"- {signal}" for signal in research.detection_signals[:8])
    if research.patched_version:
        lines.append(f"First patched version: {research.patched_version}")
    if research.reference_insights:
        lines.append("From the references:")
        lines.extend(f"- {insight}" for insight in research.reference_insights[:8])
    if research.testability_note:
        lines.append(f"Testability: {research.testability_note}")
    return "\n".join(lines)


async def design_checks(
    llm: LLMClient,
    *,
    cve: am.CveRecord,
    ranges: list[am.CveAffected],
    asset: am.Asset,
    services: list[am.AssetService],
    research: CveResearch | None = None,
) -> DetectionPlan:
    """Ask the model for a read-only detection plan."""
    hosts = ", ".join(sorted({service.host for service in services})) or "(none recorded)"
    prompt = (
        f"{_render_cve(cve, ranges)}\n\n{_render_references(cve)}\n\n"
        f"{_render_research(research)}\n\n{_render_asset(asset, services)}\n\n"
        "Design the smallest set of read-only requests that would tell an affected build "
        "from a patched one on this asset. You may only use GET, HEAD or OPTIONS, only "
        f"these hosts ({hosts}), and no request body may change state. Prefer requests "
        "that disclose a precise build version (status pages, version endpoints, static "
        "manifests, headers) over guessing at payloads. Every check must say what "
        "observation would decide the question."
    )
    result = await llm.generate_structured_output(
        prompt=prompt,
        response_model=DetectionPlan,
        system_prompt=(
            "You verify whether a specific CVE affects a specific asset. You are a careful "
            "engineer, not an attacker: you design detection checks that are read-only and "
            "safe to run in production, and you never assume a version proves exploitability."
        ),
        usage_context=_usage_context(cve.id, "cve.plan", asset.id),
    )
    plan = result.parsed_output or DetectionPlan(reasoning=result.error or "no plan", checks=[])
    return plan


def _allowed_hosts(services: list[am.AssetService]) -> set[str]:
    return {(service.host or "").strip().lower() for service in services if service.host}


def _check_url_allowed(url: str, allowed: set[str]) -> tuple[bool, str]:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "only http/https"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "no host"
    if host not in allowed:
        return False, f"{host} is not one of the asset's hosts"
    return True, ""


async def run_plan(
    plan: DetectionPlan, *, services: list[am.AssetService]
) -> list[dict[str, Any]]:
    """Execute the plan inside the safety envelope; never raises per check."""
    allowed = _allowed_hosts(services)
    observations: list[dict[str, Any]] = []
    if not plan.non_destructive:
        return [
            {
                "error": "the model's plan was not marked non-destructive, so nothing ran",
                "checks": len(plan.checks),
            }
        ]

    async with httpx.AsyncClient(
        timeout=CHECK_TIMEOUT_SECONDS, follow_redirects=False, verify=False
    ) as client:
        for index, check in enumerate(plan.checks[:MAX_CHECKS], 1):
            method = check.method.upper()
            if method not in SAFE_METHODS:
                observations.append(
                    {"n": index, "url": check.url, "error": f"refused method {method}"}
                )
                continue
            ok, why = _check_url_allowed(check.url, allowed)
            if not ok:
                observations.append(
                    {"n": index, "url": check.url, "error": f"refused url: {why}"}
                )
                continue
            try:
                response = await client.request(method, check.url)
                body = response.text if method != "HEAD" else ""
                observations.append(
                    {
                        "n": index,
                        "method": method,
                        "url": check.url,
                        "status": response.status_code,
                        "headers": {
                            k: v
                            for k, v in response.headers.items()
                            if k.lower() in ("server", "x-powered-by", "via", "x-aspnet-version")
                        },
                        "body": body[:MAX_BODY_CHARS],
                        "decides": check.decides,
                    }
                )
            except Exception as exc:  # noqa: BLE001 — a failed check is an observation
                observations.append(
                    {"n": index, "url": check.url, "error": f"{type(exc).__name__}: {exc}"}
                )
    return observations


def _render_observations(observations: list[dict[str, Any]]) -> str:
    if not observations:
        return "No checks were run."
    lines = []
    for observation in observations:
        if observation.get("error"):
            lines.append(f"[{observation.get('n')}] {observation.get('url')} → error: {observation['error']}")
            continue
        lines.append(
            f"[{observation['n']}] {observation.get('method')} {observation.get('url')} → "
            f"HTTP {observation.get('status')}"
        )
        if observation.get("headers"):
            lines.append(f"    headers: {json.dumps(observation['headers'])[:400]}")
        if observation.get("body"):
            lines.append(f"    body: {observation['body'][:1200]}")
    return "\n".join(lines)


def _enforce_evidence(decision: VerdictDecision, observations: list[dict[str, Any]]) -> VerdictDecision:
    """A verdict of applicable/not_applicable must point at something observed."""
    if decision.verdict == am.UNDETERMINED:
        return decision
    index = decision.deciding_check
    if index is None:
        return decision.model_copy(
            update={
                "verdict": am.UNDETERMINED,
                "confidence": "low",
                "reason": decision.reason
                + " (downgraded: no deciding observation was named)",
            }
        )
    usable = [
        observation
        for observation in observations
        if observation.get("n") == index and not observation.get("error")
    ]
    if not usable:
        return decision.model_copy(
            update={
                "verdict": am.UNDETERMINED,
                "confidence": "low",
                "reason": decision.reason
                + f" (downgraded: check {index} produced no usable observation)",
            }
        )
    return decision


async def judge(
    llm: LLMClient,
    *,
    cve: am.CveRecord,
    ranges: list[am.CveAffected],
    asset: am.Asset,
    services: list[am.AssetService],
    plan: DetectionPlan,
    observations: list[dict[str, Any]],
    research: CveResearch | None = None,
) -> VerdictDecision:
    """Ask the model what the observations prove, then enforce the evidence rule."""
    prompt = (
        f"{_render_cve(cve, ranges)}\n\n{_render_research(research)}\n\n"
        f"{_render_asset(asset, services)}\n\n"
        f"Detection plan: {plan.reasoning}\n\n"
        f"Observations:\n{_render_observations(observations)}\n\n"
        "Decide whether this CVE affects this asset. Name the check that decided it. If the "
        "observations repeat the version you already had, or a request failed, the honest "
        "answer is undetermined — a version number alone does not prove exploitability, and "
        "a distribution may have backported the fix without changing it."
    )
    result = await llm.generate_structured_output(
        prompt=prompt,
        response_model=VerdictDecision,
        system_prompt=(
            "You decide CVE applicability from evidence. You never claim a vulnerability was "
            "confirmed unless an observation showed it. For a patched-looking vendor build you "
            "say so plainly."
        ),
        usage_context=_usage_context(cve.id, "cve.judge", asset.id),
    )
    decision = result.parsed_output or VerdictDecision(
        verdict=am.UNDETERMINED, confidence="low", reason=result.error or "no decision"
    )
    return _enforce_evidence(decision, observations)


async def _research_without_probe(
    cve: am.CveRecord, ranges: list[am.CveAffected], technologies: list[am.AssetTechnology]
) -> Optional[dict[str, Any]]:
    """Research for an asset that cannot be reached, so the operator still learns why.

    Uses the stored record and references only — no model call, because there is
    nothing to design a check against until a host exists.
    """
    if not technologies and not (cve.references or cve.description):
        return None
    return {
        "mechanism": (cve.description or "")[:1500],
        "detection_signals": [
            f"running {tech.product} {tech.version or '(version unknown)'}"
            for tech in technologies[:6]
        ],
        "patched_version": None,
        "reference_insights": [
            reference.get("url") for reference in (cve.references or [])[:6] if reference.get("url")
        ],
        "testability_note": (
            "recorded from the asset's technologies; no request was made because the "
            "asset has no reachable endpoint"
        ),
    }


async def verify_verdict(verdict_id: uuid.UUID, *, llm_config_id: Optional[uuid.UUID] = None) -> dict[str, Any]:
    """Verify one observed candidate verdict end to end and store the result."""
    async with AsyncSessionLocal() as db:
        verdict = await db.get(am.AssetCveVerdict, verdict_id)
        if verdict is None:
            return {"error": "verdict not found"}
        asset = await db.get(am.Asset, verdict.asset_id)
        cve = await db.get(am.CveRecord, verdict.cve_id)
        if asset is None or cve is None:
            return {"error": "asset or CVE missing"}
        services = list(
            await db.scalars(select(am.AssetService).where(am.AssetService.asset_id == asset.id))
        )
        technologies = list(
            await db.scalars(
                select(am.AssetTechnology).where(am.AssetTechnology.asset_id == asset.id)
            )
        )
        ranges = list(
            await db.scalars(select(am.CveAffected).where(am.CveAffected.cve_id == cve.id))
        )
        if not services:
            # A database, firewall or Kubernetes cluster may have a version and no
            # URL. Research still tells the operator what would prove it, and the
            # verdict stays undetermined rather than pretending a test happened.
            research_only = await _research_without_probe(cve, ranges, technologies)
            if research_only is not None:
                verdict.research = research_only
                verdict.verdict = am.UNDETERMINED
                verdict.confidence = "low"
                verdict.reason = (
                    "No reachable endpoint is recorded for this asset, so the CVE could "
                    "not be tested. Record a host/port (or probe the asset) to verify it."
                )
                await db.commit()
                return {
                    "verdict_id": str(verdict.id),
                    "cve_id": verdict.cve_id,
                    "asset_id": str(verdict.asset_id),
                    "verdict": verdict.verdict,
                    "confidence": verdict.confidence,
                    "reason": verdict.reason,
                    "checks": 0,
                }
            return {"error": "the asset has no services to test"}

        if llm_config_id is None:
            from app.pentest.engine import resolve_default_llm_config_id

            llm_config_id = await resolve_default_llm_config_id()
        if llm_config_id is None:
            return {"error": "no LLM configuration is available"}

        llm = await get_llm_client(llm_config_id)
        if llm is None:
            return {"error": "could not initialise the LLM client"}

        research = await research_cve(llm, cve=cve, ranges=ranges, asset=asset)

        # One check per CVE, stored and replayed: the same software is tested the same
        # way on every asset, and a human can read the check that produced a verdict.
        stored = await checks.load_template(cve.id)
        template_source = "stored"
        if stored is None:
            generated = await design_template(
                llm, cve=cve, ranges=ranges, research=research, asset=asset
            )
            if generated:
                await checks.store_template(cve.id, generated)
                stored = await checks.load_template(cve.id)
                template_source = "generated"
        template_text = stored.template if stored is not None else ""
        template_observations: list[dict[str, Any]] = []
        template_summary: dict[str, Any] = {}
        if template_text:
            try:
                template_observations = await checks.run_template(
                    template_text, services=services
                )
                template_summary = checks.summarise(template_observations)
            except checks.TemplateInvalid as exc:
                logger.warning("stored template for %s is unusable: %s", cve.id, exc)
                template_summary = {"error": str(exc)}

        plan = await design_checks(
            llm, cve=cve, ranges=ranges, asset=asset, services=services, research=research
        )
        observations = await run_plan(plan, services=services)
        # The template's findings are evidence too: show them to the judge.
        if template_summary.get("matched"):
            observations = observations + [
                {
                    "n": len(observations) + 1,
                    "method": row.get("method"),
                    "url": row.get("url"),
                    "status": row.get("status"),
                    "headers": row.get("headers"),
                    "body": row.get("body"),
                    "decides": "matched the stored detection template",
                }
                for row in template_observations
                if row.get("matched")
            ]
        decision = await judge(
            llm,
            cve=cve,
            ranges=ranges,
            asset=asset,
            services=services,
            plan=plan,
            observations=observations,
            research=research,
        )

        verdict.verdict = decision.verdict
        verdict.confidence = decision.confidence
        verdict.reason = decision.reason
        verdict.research = research.model_dump()
        verdict.probe = {
            "plan": plan.model_dump(),
            "observations": observations,
            "deciding_check": decision.deciding_check,
            "template": {
                "source": template_source,
                "yaml": template_text,
                "summary": template_summary,
            },
        }
        # A probe is a stronger basis than a banner, so the row moves to it rather
        # than keeping a stale observed row beside a tested one.
        verdict.basis = am.BASIS_PROBE
        await db.commit()

        from app.assets import matcher

        return {
            "verdict_id": str(verdict.id),
            "cve_id": verdict.cve_id,
            "asset_id": str(verdict.asset_id),
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "checks": len(observations),
            "needs_verification": matcher.needs_verification(verdict),
        }
