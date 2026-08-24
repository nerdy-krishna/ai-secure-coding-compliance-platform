from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from app.api.v1.schemas.rule_foundry import ReviewDecision
from app.core.services.rule_foundry_service import RuleFoundryService
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.rule_foundry_repo import (
    RuleFoundryRepository,
)
from app.infrastructure.signing.digest_signer import LocalTestDigestSigner
from app.shared.lib.rule_foundry import canonical_digest
from tests.unit.test_rule_foundry_policy import passing_metrics


class _Evaluator:
    async def evaluate(self, **_kwargs):
        return passing_metrics()


class _Authz:
    async def separation_of_duties_mode(self, **_kwargs):
        return "off"


class _Db:
    def __init__(self, repo) -> None:
        self.repo = repo

    def add(self, row) -> None:
        if isinstance(row, db_models.RuleFoundryDeployment):
            self.repo.active = row

    async def get(self, model, row_id):
        if model is db_models.RuleFoundryVersion:
            return next((row for row in self.repo.versions if row.id == row_id), None)
        return None


class _Repo:
    def __init__(self, candidate, version, deployment) -> None:
        self.candidate = candidate
        self.versions = [version]
        self.active = deployment
        self.events = []
        self.db = _Db(self)

    async def get_candidate(self, **_kwargs):
        return self.candidate

    async def active_deployment(self, **_kwargs):
        return self.active

    async def candidate_payload(self, _candidate):
        return {
            "id": "tenant.rule",
            "languages": ["python"],
            "message": "x",
            "severity": "ERROR",
            "pattern": "danger(...)",
        }

    async def baseline_median_ms(self):
        return "100"

    async def latest_version(self, **_kwargs):
        return self.versions[-1]

    async def add_version(self, **kwargs):
        row = SimpleNamespace(
            id=uuid4(),
            tenant_id=kwargs["tenant_id"],
            candidate_id=kwargs["candidate_id"],
            version=len(self.versions) + 1,
            canonical_payload=kwargs["canonical_payload"],
            payload_sha256=kwargs["payload_sha256"],
            signature=kwargs["signature"],
            signature_algorithm=kwargs["signature_algorithm"],
            signing_key_id=kwargs["signing_key_id"],
            quality_metrics=kwargs["quality_metrics"],
            reviewer_decision=kwargs["reviewer_decision"],
            reviewer_user_id=kwargs["reviewer_user_id"],
            created_at=datetime.now(timezone.utc),
        )
        self.versions.append(row)
        return row

    async def add_event(self, **kwargs):
        self.events.append(kwargs)

    async def shadow_totals(self, **_kwargs):
        return 100, 1


class RuleFoundryLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_unpromoted_expiry_persists_status_and_audit_event(self) -> None:
        candidate = SimpleNamespace(
            id=uuid4(),
            tenant_id=uuid4(),
            status="pending_review",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )

        class _Rows:
            def all(self):
                return [candidate]

        added = []
        db = SimpleNamespace(
            scalars=AsyncMock(return_value=_Rows()),
            add=lambda row: added.append(row),
        )
        count = await RuleFoundryRepository(db).expire_due(
            tenant_id=candidate.tenant_id,
            now=datetime.now(timezone.utc),
        )
        self.assertEqual(count, 1)
        self.assertEqual(candidate.status, "expired")
        self.assertEqual(added[0].action, "expired")

    async def test_v2_shadow_promotion_and_rollback_restores_v1(self) -> None:
        signer = LocalTestDigestSigner()
        tenant_id = uuid4()
        candidate_id = uuid4()
        v1_payload = {"rule": {"id": "tenant.rule.v1"}}
        _encoded, v1_digest = canonical_digest(v1_payload)
        v1_signature = await signer.sign_sha256(bytes.fromhex(v1_digest))
        v1 = SimpleNamespace(
            id=uuid4(),
            tenant_id=tenant_id,
            candidate_id=candidate_id,
            version=1,
            canonical_payload=v1_payload,
            payload_sha256=v1_digest,
            signature=v1_signature.signature_b64,
            signature_algorithm=v1_signature.algorithm,
            signing_key_id=v1_signature.key_id,
        )
        candidate = SimpleNamespace(
            id=candidate_id,
            tenant_id=tenant_id,
            status="promoted",
            static_representable=True,
            registry_kind="semgrep",
            creator_user_id=10,
            reviewer_user_id=11,
            promoter_user_id=12,
            normalized_evidence={"lineage": "kept"},
            fixtures={"vulnerable": [{}]},
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            reviewed_at=None,
            promoted_at=datetime.now(timezone.utc),
        )
        v1_deployment = db_models.RuleFoundryDeployment(
            id=uuid4(),
            tenant_id=tenant_id,
            candidate_id=candidate_id,
            version_id=v1.id,
            prior_version_id=None,
            state="promoted",
            actor_user_id=12,
            promoted_at=datetime.now(timezone.utc),
        )
        repo = _Repo(candidate, v1, v1_deployment)
        service = RuleFoundryService(
            repo=repo,  # type: ignore[arg-type]
            authz_repo=_Authz(),  # type: ignore[arg-type]
            signer=signer,
            evaluator=_Evaluator(),
        )

        await service.mark_review_required(
            tenant_id=tenant_id,
            actor_user_id=12,
            candidate_id=candidate_id,
            trigger="tool_incompatibility",
            reason="Semgrep compatibility changed",
        )
        await service.review_candidate(
            tenant_id=tenant_id,
            actor_user_id=11,
            candidate_id=candidate_id,
            decision=ReviewDecision(
                approved=True, reason="v2 fixtures independently reviewed"
            ),
        )
        v2 = repo.versions[-1]
        await service.start_shadow(
            tenant_id=tenant_id,
            actor_user_id=12,
            candidate_id=candidate_id,
            reason="shadow v2",
        )
        self.assertEqual(repo.active.version_id, v2.id)
        self.assertEqual(repo.active.prior_version_id, v1.id)
        self.assertEqual(v1_deployment.state, "superseded")

        await service.promote(
            tenant_id=tenant_id,
            actor_user_id=12,
            candidate_id=candidate_id,
            reason="shadow gate passed",
        )
        self.assertEqual(repo.active.state, "promoted")
        await service.rollback(
            tenant_id=tenant_id,
            actor_user_id=12,
            candidate_id=candidate_id,
            reason="unexpected post-promotion regression",
        )
        self.assertEqual(repo.active.version_id, v1.id)
        self.assertEqual(repo.active.state, "promoted")
        self.assertEqual(candidate.status, "promoted")
        self.assertEqual(repo.events[-1]["action"], "rolled_back")


if __name__ == "__main__":
    unittest.main()
