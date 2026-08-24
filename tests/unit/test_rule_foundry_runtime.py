from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from app.core.schemas import VulnerabilityFinding
from app.core.services.rule_foundry_runtime import (
    ActiveFoundryRule,
    build_promoted_osv_findings,
    load_active_rules,
    osv_observation_counts,
    record_shadow_observation_safely,
    retain_promoted_findings,
)
from app.infrastructure.signing.digest_signer import LocalTestDigestSigner
from app.shared.lib.rule_foundry import assert_shadow_gate, canonical_digest


class _SessionContext:
    def __init__(self, db) -> None:
        self.db = db

    async def __aenter__(self):
        return self.db

    async def __aexit__(self, *_args):
        return False


class _FailingSessionContext:
    async def __aenter__(self):
        raise RuntimeError("database unavailable")

    async def __aexit__(self, *_args):
        return False


class _Rows:
    def __init__(self, rows) -> None:
        self.rows = rows

    def all(self):
        return self.rows


class _RuntimeDb:
    def __init__(self, rows, versions=None) -> None:
        self.rows = rows
        self.versions = versions or {}
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        return _Rows(self.rows)

    async def get(self, _model, row_id):
        return self.versions.get(row_id)


class RuleFoundryRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def _rule(
        self,
        *,
        registry_kind: str = "semgrep",
        mode: str = "shadow",
        payload=None,
    ) -> ActiveFoundryRule:
        return ActiveFoundryRule(
            tenant_id=uuid4(),
            candidate_id=uuid4(),
            deployment_id=uuid4(),
            version_id=uuid4(),
            registry_kind=registry_kind,
            mode=mode,
            payload=payload or {"id": "candidate", "pattern": "$X"},
            severity="high",
            cwe="CWE-79",
        )

    async def test_shadow_emission_is_bounded_and_attempt_bound(self) -> None:
        rule = self._rule()
        scan_id = uuid4()
        attempt_id = uuid4()
        db = SimpleNamespace(
            get=AsyncMock(
                return_value=SimpleNamespace(
                    id=scan_id,
                    tenant_id=rule.tenant_id,
                    current_attempt_id=attempt_id,
                )
            ),
            commit=AsyncMock(),
        )
        recorder = AsyncMock()
        fake_service = SimpleNamespace(record_shadow_observation=recorder)
        with (
            patch(
                "app.core.services.rule_foundry_runtime.AsyncSessionLocal",
                return_value=_SessionContext(db),
            ),
            patch(
                "app.core.services.rule_foundry_runtime.RuleFoundryService",
                return_value=fake_service,
            ),
        ):
            emitted = await record_shadow_observation_safely(
                rule=rule,
                scan_id=scan_id,
                eligible_files=9_000,
                unexpected_matches=8_000,
            )
        self.assertTrue(emitted)
        recorder.assert_awaited_once_with(
            tenant_id=rule.tenant_id,
            candidate_id=rule.candidate_id,
            scan_id=scan_id,
            attempt_id=attempt_id,
            eligible_files=5000,
            unexpected_matches=5000,
        )
        db.commit.assert_awaited_once()

    async def test_observation_failure_never_breaks_scan(self) -> None:
        with patch(
            "app.core.services.rule_foundry_runtime.AsyncSessionLocal",
            return_value=_FailingSessionContext(),
        ):
            emitted = await record_shadow_observation_safely(
                rule=self._rule(),
                scan_id=uuid4(),
                eligible_files=100,
                unexpected_matches=0,
            )
        self.assertFalse(emitted)

    async def test_all_registry_payloads_require_valid_signature_and_tenant(
        self,
    ) -> None:
        signer = LocalTestDigestSigner()
        tenant_id = uuid4()
        payloads = {
            "semgrep": {"id": "sg", "languages": ["python"], "pattern": "$X"},
            "gitleaks": {"id": "gl", "regex": "token-[0-9]+"},
            "osv": {
                "id": "OSV-TENANT-1",
                "affected": [
                    {
                        "package": {"name": "demo", "ecosystem": "PyPI"},
                        "versions": ["1.2.3"],
                    }
                ],
            },
        }
        for registry_kind, rule_payload in payloads.items():
            candidate_id = uuid4()
            version_id = uuid4()
            envelope = {"rule": rule_payload}
            _encoded, digest = canonical_digest(envelope)
            signature = await signer.sign_sha256(bytes.fromhex(digest))
            candidate = SimpleNamespace(
                id=candidate_id,
                tenant_id=tenant_id,
                registry_kind=registry_kind,
                severity="high",
                cwe="CWE-79",
            )
            deployment = SimpleNamespace(
                id=uuid4(),
                tenant_id=tenant_id,
                candidate_id=candidate_id,
                version_id=version_id,
                prior_version_id=None,
                state="promoted",
                promoted_at=SimpleNamespace(),
            )
            version = SimpleNamespace(
                id=version_id,
                tenant_id=tenant_id,
                candidate_id=candidate_id,
                canonical_payload=envelope,
                payload_sha256=digest,
                signature=signature.signature_b64,
                signature_algorithm=signature.algorithm,
                signing_key_id=signature.key_id,
            )
            rules = await load_active_rules(
                db=_RuntimeDb([(candidate, deployment, version)]),  # type: ignore[arg-type]
                tenant_id=tenant_id,
                registry_kind=registry_kind,
                signer=signer,
            )
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0].tenant_id, tenant_id)
            self.assertEqual(rules[0].registry_kind, registry_kind)
            self.assertEqual(rules[0].payload, rule_payload)

            version.signature = "invalid"
            invalid = await load_active_rules(
                db=_RuntimeDb([(candidate, deployment, version)]),  # type: ignore[arg-type]
                tenant_id=tenant_id,
                registry_kind=registry_kind,
                signer=signer,
            )
            self.assertEqual(invalid, [])
            if registry_kind == "semgrep":
                version.signature = signature.signature_b64
                deployment.state = "review_required"
                deployment.promoted_at = None
                overdue_shadow = await load_active_rules(
                    db=_RuntimeDb([(candidate, deployment, version)]),  # type: ignore[arg-type]
                    tenant_id=tenant_id,
                    registry_kind=registry_kind,
                    signer=signer,
                )
                self.assertEqual(overdue_shadow, [])

    async def test_runtime_rejects_cross_tenant_rows_even_with_valid_signature(
        self,
    ) -> None:
        signer = LocalTestDigestSigner()
        requested_tenant = uuid4()
        foreign_tenant = uuid4()
        candidate_id = uuid4()
        version_id = uuid4()
        envelope = {"rule": {"id": "foreign", "pattern": "$X"}}
        _encoded, digest = canonical_digest(envelope)
        signature = await signer.sign_sha256(bytes.fromhex(digest))
        candidate = SimpleNamespace(
            id=candidate_id,
            tenant_id=foreign_tenant,
            registry_kind="semgrep",
            severity="medium",
            cwe=None,
        )
        deployment = SimpleNamespace(
            id=uuid4(),
            tenant_id=foreign_tenant,
            candidate_id=candidate_id,
            version_id=version_id,
            prior_version_id=None,
            state="promoted",
            promoted_at=SimpleNamespace(),
        )
        version = SimpleNamespace(
            id=version_id,
            tenant_id=foreign_tenant,
            candidate_id=candidate_id,
            canonical_payload=envelope,
            payload_sha256=digest,
            signature=signature.signature_b64,
            signature_algorithm=signature.algorithm,
            signing_key_id=signature.key_id,
        )
        rules = await load_active_rules(
            db=_RuntimeDb([(candidate, deployment, version)]),  # type: ignore[arg-type]
            tenant_id=requested_tenant,
            registry_kind="semgrep",
            signer=signer,
        )
        self.assertEqual(rules, [])

    def test_shadow_findings_are_excluded_and_promoted_provenance_survives(
        self,
    ) -> None:
        promoted = self._rule(mode="promoted")
        shadow = self._rule(mode="shadow")

        def finding(rule, source):
            return VulnerabilityFinding(
                cwe="CWE-79",
                title="Foundry match",
                description="Reviewed deterministic match.",
                severity="High",
                line_number=1,
                remediation="Fix it.",
                confidence="High",
                references=[],
                cvss_score=None,
                cvss_vector=None,
                file_path="app.py",
                fixes=None,
                source=source,
                scanner_rule_id=f"foundry.{rule.candidate_id}.{rule.version_id}",
                agent_name=None,
                corroborating_agents=None,
                is_applied_in_remediation=False,
            )

        for source in ("semgrep", "gitleaks"):
            retained = retain_promoted_findings(
                [promoted, shadow],
                [finding(promoted, source), finding(shadow, source)],
            )
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].source, source)
            self.assertEqual(
                retained[0].scanner_rule_id,
                f"foundry.{promoted.candidate_id}.{promoted.version_id}",
            )

        osv_payload = {
            "id": "OSV-TENANT-1",
            "affected": [
                {
                    "package": {"name": "demo", "ecosystem": "PyPI"},
                    "versions": ["1.2.3"],
                }
            ],
        }
        promoted_osv = self._rule(
            registry_kind="osv", mode="promoted", payload=osv_payload
        )
        shadow_osv = self._rule(registry_kind="osv", mode="shadow", payload=osv_payload)
        osv_findings = build_promoted_osv_findings(
            [promoted_osv, shadow_osv],
            {
                "components": [
                    {"name": "demo", "version": "1.2.3", "purl": "pkg:pypi/demo@1.2.3"}
                ]
            },
        )
        self.assertEqual(len(osv_findings), 1)
        self.assertEqual(osv_findings[0].source, "osv")
        self.assertEqual(
            osv_findings[0].scanner_rule_id,
            f"foundry.{promoted_osv.candidate_id}.{promoted_osv.version_id}",
        )

    def test_osv_shadow_gate_counts_unique_dependency_units(self) -> None:
        rule = self._rule(
            registry_kind="osv",
            mode="shadow",
            payload={
                "id": "OSV-TENANT-1",
                "affected": [
                    {
                        "package": {"name": "demo", "ecosystem": "PyPI"},
                        "versions": ["1.2.3"],
                    }
                ],
            },
        )
        components = [
            {"name": "demo", "version": "1.2.3", "purl": "pkg:pypi/demo@1.2.3"}
        ]
        components.extend(
            {
                "name": f"clean-{index}",
                "version": "1.0.0",
                "purl": f"pkg:pypi/clean-{index}@1.0.0",
            }
            for index in range(99)
        )
        eligible, unexpected = osv_observation_counts(rule, {"components": components})
        self.assertEqual((eligible, unexpected), (100, 1))
        assert_shadow_gate(
            eligible_files=eligible,
            unexpected_matches=unexpected,
        )


if __name__ == "__main__":
    unittest.main()
