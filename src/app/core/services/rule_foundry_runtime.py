"""Verified tenant rule selection and failure-isolated shadow telemetry hooks."""

from __future__ import annotations

import hmac
import logging
import uuid
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.core.schemas import VulnerabilityFinding
from app.core.services.rule_foundry_service import RuleFoundryService
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
)
from app.infrastructure.database.repositories.rule_foundry_repo import (
    RuleFoundryRepository,
)
from app.infrastructure.database.tenant_context import system_principal_task
from app.infrastructure.signing.digest_signer import (
    AwsKmsDigestSigner,
    DigestSignature,
    DigestSigner,
)
from app.shared.lib.rule_foundry import canonical_digest


logger = logging.getLogger(__name__)
MAX_OSV_OBSERVATION_COMPONENTS = 5000


@dataclass(frozen=True)
class ActiveFoundryRule:
    tenant_id: uuid.UUID
    candidate_id: uuid.UUID
    deployment_id: uuid.UUID
    version_id: uuid.UUID
    registry_kind: str
    mode: str
    payload: dict[str, Any]
    severity: str
    cwe: str | None

    def as_semgrep_rule(self) -> SimpleNamespace:
        rule = dict(self.payload)
        rule["id"] = f"foundry.{self.candidate_id}.{self.version_id}"
        return SimpleNamespace(
            namespaced_id=rule["id"],
            raw_yaml=rule,
            source_id=None,
            source=None,
        )

    def as_gitleaks_rule(self) -> dict[str, Any]:
        rule = dict(self.payload)
        rule["id"] = f"foundry.{self.candidate_id}.{self.version_id}"
        return rule


def build_runtime_signer() -> DigestSigner | None:
    if not settings.RULE_FOUNDRY_KMS_KEY_ID:
        return None
    return AwsKmsDigestSigner(
        key_id=settings.RULE_FOUNDRY_KMS_KEY_ID,
        region=settings.RULE_FOUNDRY_KMS_REGION,
    )


async def load_active_rules(
    *,
    db: AsyncSession,
    tenant_id: uuid.UUID,
    registry_kind: str,
    signer: DigestSigner | None = None,
) -> list[ActiveFoundryRule]:
    rows = (
        await db.execute(
            select(
                db_models.RuleFoundryCandidate,
                db_models.RuleFoundryDeployment,
                db_models.RuleFoundryVersion,
            )
            .join(
                db_models.RuleFoundryDeployment,
                db_models.RuleFoundryDeployment.candidate_id
                == db_models.RuleFoundryCandidate.id,
            )
            .join(
                db_models.RuleFoundryVersion,
                db_models.RuleFoundryVersion.id
                == db_models.RuleFoundryDeployment.version_id,
            )
            .where(
                db_models.RuleFoundryCandidate.tenant_id == tenant_id,
                db_models.RuleFoundryCandidate.registry_kind == registry_kind,
                db_models.RuleFoundryDeployment.ended_at.is_(None),
                db_models.RuleFoundryDeployment.state.in_(
                    ("shadow", "promoted", "review_required")
                ),
            )
        )
    ).all()
    if not rows:
        return []
    verifier = signer or build_runtime_signer()
    if verifier is None:
        logger.error(
            "rule_foundry.runtime.signer_unavailable",
            extra={"tenant_id": str(tenant_id), "registry": registry_kind},
        )
        return []
    active: list[ActiveFoundryRule] = []
    for candidate, deployment, version in rows:
        if (
            candidate.tenant_id != tenant_id
            or candidate.registry_kind != registry_kind
            or deployment.tenant_id != tenant_id
            or deployment.candidate_id != candidate.id
            or version.tenant_id != tenant_id
            or version.candidate_id != candidate.id
            or version.id != deployment.version_id
        ):
            logger.error(
                "rule_foundry.runtime.tenant_or_lineage_mismatch",
                extra={
                    "candidate_id": str(candidate.id),
                    "deployment_id": str(deployment.id),
                },
            )
            continue
        if deployment.state == "shadow":
            versions = [(version, "shadow")]
        elif deployment.state == "promoted" or (
            deployment.state == "review_required" and deployment.promoted_at is not None
        ):
            versions = [(version, "promoted")]
        else:
            # An overdue shadow is review-required but never becomes policy-visible.
            continue
        # During vNext shadow, the explicitly carried prior signed version
        # remains operational until promotion or rollback.
        if deployment.state == "shadow" and deployment.prior_version_id is not None:
            prior = await db.get(
                db_models.RuleFoundryVersion, deployment.prior_version_id
            )
            if (
                prior is not None
                and prior.tenant_id == tenant_id
                and prior.candidate_id == candidate.id
            ):
                versions.append((prior, "promoted"))
        for selected_version, mode in versions:
            _encoded, recomputed = canonical_digest(selected_version.canonical_payload)
            if not hmac.compare_digest(recomputed, selected_version.payload_sha256):
                logger.error(
                    "rule_foundry.runtime.payload_digest_mismatch",
                    extra={
                        "candidate_id": str(candidate.id),
                        "version_id": str(selected_version.id),
                    },
                )
                continue
            valid = await verifier.verify_sha256(
                bytes.fromhex(selected_version.payload_sha256),
                DigestSignature(
                    signature_b64=selected_version.signature,
                    algorithm=selected_version.signature_algorithm,
                    key_id=selected_version.signing_key_id,
                ),
            )
            if not valid:
                logger.error(
                    "rule_foundry.runtime.signature_invalid",
                    extra={
                        "candidate_id": str(candidate.id),
                        "version_id": str(selected_version.id),
                    },
                )
                continue
            rule = selected_version.canonical_payload.get("rule")
            if not isinstance(rule, dict):
                continue
            active.append(
                ActiveFoundryRule(
                    tenant_id=tenant_id,
                    candidate_id=candidate.id,
                    deployment_id=deployment.id,
                    version_id=selected_version.id,
                    registry_kind=registry_kind,
                    mode=mode,
                    payload=dict(rule),
                    severity=candidate.severity,
                    cwe=candidate.cwe,
                )
            )
    return active


def retain_promoted_findings(
    rules: list[ActiveFoundryRule],
    findings: list[VulnerabilityFinding],
) -> list[VulnerabilityFinding]:
    """Allow only findings attributable to explicitly promoted rule versions."""

    promoted_ids = {
        f"foundry.{rule.candidate_id}.{rule.version_id}"
        for rule in rules
        if rule.mode == "promoted"
    }
    return [finding for finding in findings if finding.scanner_rule_id in promoted_ids]


def build_promoted_osv_findings(
    rules: list[ActiveFoundryRule],
    bom: dict[str, Any] | None,
) -> list[VulnerabilityFinding]:
    """Build policy-visible OSV findings only from promoted signed versions."""

    findings: list[VulnerabilityFinding] = []
    for rule in rules:
        if rule.mode != "promoted":
            continue
        for component in match_osv_components(rule, bom):
            advisory_id = str(rule.payload.get("id") or "tenant-advisory")
            severity = rule.severity.capitalize()
            if severity not in {
                "Critical",
                "High",
                "Medium",
                "Low",
                "Informational",
            }:
                severity = "Medium"
            findings.append(
                VulnerabilityFinding(
                    cwe=rule.cwe,
                    title=f"Tenant advisory: {advisory_id}"[:200],
                    description=(
                        f"Signed tenant advisory {advisory_id} matches "
                        f"{component['name']} {component['version']}."
                    ),
                    severity=severity,
                    line_number=0,
                    remediation=(
                        "Upgrade to a version outside the reviewed affected set."
                    ),
                    confidence="High",
                    references=[],
                    cvss_score=None,
                    cvss_vector=None,
                    file_path="<repository>",
                    fixes=None,
                    source="osv",
                    scanner_rule_id=f"foundry.{rule.candidate_id}.{rule.version_id}",
                    agent_name=None,
                    corroborating_agents=None,
                    is_applied_in_remediation=False,
                )
            )
    return findings


def match_osv_components(
    rule: ActiveFoundryRule, bom: dict[str, Any] | None
) -> list[dict[str, str]]:
    """Match bounded exact-version OSV candidates against retained CycloneDX."""

    if not bom:
        return []
    matched: list[dict[str, str]] = []
    for component in (bom.get("components", []) or [])[:MAX_OSV_OBSERVATION_COMPONENTS]:
        if not isinstance(component, dict):
            continue
        name = str(component.get("name") or "")
        version = str(component.get("version") or "")
        ecosystem = str(component.get("ecosystem") or "")
        purl = str(component.get("purl") or "")
        for affected in rule.payload.get("affected", []) or []:
            package = affected.get("package", {}) if isinstance(affected, dict) else {}
            expected_name = str(package.get("name") or "")
            expected_ecosystem = str(package.get("ecosystem") or "")
            ecosystem_matches = not expected_ecosystem or (
                ecosystem.lower() == expected_ecosystem.lower()
                or f"pkg:{expected_ecosystem.lower()}/" in purl.lower()
            )
            if (
                name == expected_name
                and ecosystem_matches
                and version in {str(value) for value in affected.get("versions", [])}
            ):
                matched.append({"name": name, "version": version, "purl": purl[:512]})
                break
    return matched


def osv_observation_counts(
    rule: ActiveFoundryRule,
    bom: dict[str, Any] | None,
) -> tuple[int, int]:
    """Count bounded unique dependency units and matching units for shadow quality."""

    if not bom:
        return 0, 0
    eligible = {
        (
            str(component.get("name") or "")[:256],
            str(component.get("version") or "")[:128],
            str(component.get("purl") or "")[:512],
        )
        for component in (bom.get("components", []) or [])[
            :MAX_OSV_OBSERVATION_COMPONENTS
        ]
        if isinstance(component, dict)
        and component.get("name")
        and component.get("version")
    }
    matched = {
        (item["name"], item["version"], item["purl"])
        for item in match_osv_components(rule, bom)
    }
    return len(eligible), len(matched & eligible)


async def record_shadow_observation_safely(
    *,
    rule: ActiveFoundryRule,
    scan_id: uuid.UUID,
    eligible_files: int,
    unexpected_matches: int,
) -> bool:
    """Persist only bounded counts/identities; telemetry failure never fails a scan."""

    try:
        async with AsyncSessionLocal() as db:
            scan = await db.get(db_models.Scan, scan_id)
            if (
                scan is None
                or scan.current_attempt_id is None
                or scan.tenant_id != rule.tenant_id
            ):
                return False
            service = RuleFoundryService(
                repo=RuleFoundryRepository(db),
                authz_repo=AuthorizationRepository(db),
                signer=None,
            )
            await service.record_shadow_observation(
                tenant_id=rule.tenant_id,
                candidate_id=rule.candidate_id,
                scan_id=scan.id,
                attempt_id=scan.current_attempt_id,
                eligible_files=min(max(eligible_files, 0), 5000),
                unexpected_matches=min(
                    max(unexpected_matches, 0), eligible_files, 5000
                ),
            )
            await db.commit()
        return True
    except Exception:  # noqa: BLE001 - deliberate scan failure isolation
        logger.warning(
            "rule_foundry.shadow_observation_failed",
            extra={
                "tenant_id": str(rule.tenant_id),
                "candidate_id": str(rule.candidate_id),
                "deployment_id": str(rule.deployment_id),
                "scan_id": str(scan_id),
            },
            exc_info=True,
        )
        return False


@system_principal_task("rule-foundry-runtime-degradation")
async def record_promoted_degradation_safely(
    *,
    rules: list[ActiveFoundryRule],
    scan_id: uuid.UUID,
    reason_code: str,
) -> bool:
    """Append one bounded signal per candidate/scan and enforce sustained review."""

    try:
        by_candidate = {
            rule.candidate_id: rule for rule in rules if rule.mode == "promoted"
        }
        if not by_candidate:
            return True
        async with AsyncSessionLocal() as db:
            scan = await db.get(db_models.Scan, scan_id)
            if scan is None:
                return False
            repo = RuleFoundryRepository(db)
            for rule in by_candidate.values():
                if rule.tenant_id != scan.tenant_id:
                    return False
                await repo.record_promoted_degradation(
                    tenant_id=rule.tenant_id,
                    candidate_id=rule.candidate_id,
                    scan_id=scan_id,
                    reason_code=reason_code,
                )
            await db.commit()
        return True
    except (
        Exception
    ):  # noqa: BLE001 - telemetry must not replace scan failure semantics
        logger.warning(
            "rule_foundry.promoted_degradation_record_failed",
            extra={"scan_id": str(scan_id), "reason_code": reason_code[:64]},
            exc_info=True,
        )
        return False
