"""Real PostgreSQL proof for finding baseline and policy persistence."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.exc import DBAPIError

from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.repositories.finding_governance_repo import (
    FindingGovernanceRepository,
)
from app.infrastructure.database.repositories.scan_attempt_repo import (
    ScanAttemptRepository,
)
from app.infrastructure.database.tenant_context import bind_principal, reset_principal
from tests.integration.support import integration_test


@integration_test
class FindingGovernancePersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self) -> None:
        await engine.dispose()

    @staticmethod
    def finding(
        scan, *, rule: str, path: str, snippet: str, line_number: int = 10
    ) -> db_models.Finding:
        return db_models.Finding(
            scan_id=scan.id,
            tenant_id=scan.tenant_id,
            file_path=path,
            line_number=line_number,
            vulnerable_snippet=snippet,
            title=rule,
            severity="High",
            confidence="High",
            source="semgrep",
            scanner_rule_id=rule,
            finding_bucket="consolidated",
            remediation="Use the safe API.",
        )

    async def test_new_fixed_unchanged_reintroduced_and_gate_share_records(self):
        binding = bind_principal(
            tenant_id=None,
            principal_kind="system",
            principal_id="finding-governance-integration",
            system_scope=True,
        )
        try:
            async with AsyncSessionLocal() as db:
                tenant = db_models.Tenant(
                    slug=f"finding-governance-{uuid4().hex[:10]}",
                    display_name="Finding governance test",
                )
                db.add(tenant)
                await db.flush()
                user = db_models.User(
                    email=f"finding-governance-{uuid4()}@example.invalid",
                    hashed_password="not-real",
                    is_active=True,
                    is_verified=True,
                    tenant_id=tenant.id,
                )
                db.add(user)
                await db.flush()
                project = db_models.Project(
                    user_id=user.id,
                    tenant_id=tenant.id,
                    name=f"finding-governance-{uuid4()}",
                )
                db.add(project)
                await db.flush()
                start = datetime.now(timezone.utc) - timedelta(days=3)
                scans = []
                for index in range(3):
                    scan = db_models.Scan(
                        project_id=project.id,
                        user_id=user.id,
                        tenant_id=tenant.id,
                        scan_type="AUDIT",
                        status="COMPLETED" if index < 2 else "RUNNING",
                        frameworks=[],
                        summary={},
                        created_at=start + timedelta(days=index),
                        completed_at=(
                            start + timedelta(days=index, hours=1)
                            if index < 2
                            else None
                        ),
                    )
                    db.add(scan)
                    await db.flush()
                    await ScanAttemptRepository(db).create_initial(
                        scan, actor_user_id=user.id, commit=False
                    )
                    scans.append(scan)
                scan1, scan2, current = scans
                failed_partial = db_models.Scan(
                    project_id=project.id,
                    user_id=user.id,
                    tenant_id=tenant.id,
                    scan_type="AUDIT",
                    status="FAILED",
                    frameworks=[],
                    summary={},
                    created_at=start + timedelta(days=1, hours=12),
                    completed_at=None,
                )
                db.add(failed_partial)
                await db.flush()
                db.add_all(
                    [
                        self.finding(
                            scan1, rule="rule-a", path="a.py", snippet="bad_a()"
                        ),
                        self.finding(
                            scan2, rule="rule-b", path="b.py", snippet="bad_b()"
                        ),
                        self.finding(
                            scan2, rule="rule-d", path="d.py", snippet="bad_d()"
                        ),
                        self.finding(
                            scan2, rule="rule-e", path="e.py", snippet="bad_e()"
                        ),
                        self.finding(
                            scan2, rule="rule-f", path="f.py", snippet="bad_f()"
                        ),
                        self.finding(
                            scan2,
                            rule="rule-f",
                            path="f.py",
                            snippet="bad_f()",
                            line_number=30,
                        ),
                        self.finding(
                            current, rule="rule-a", path="a.py", snippet="bad_a()"
                        ),
                        self.finding(
                            current, rule="rule-b", path="b.py", snippet="bad_b()"
                        ),
                        self.finding(
                            current, rule="rule-c", path="c.py", snippet="bad_c()"
                        ),
                        self.finding(
                            current,
                            rule="rule-c",
                            path="c.py",
                            snippet="bad_c()",
                            line_number=30,
                        ),
                        self.finding(
                            current, rule="rule-e", path="e.py", snippet="bad_e()"
                        ),
                        self.finding(
                            current,
                            rule="rule-e",
                            path="e.py",
                            snippet="bad_e()",
                            line_number=30,
                        ),
                        self.finding(
                            current, rule="rule-f", path="f.py", snippet="bad_f()"
                        ),
                        self.finding(
                            failed_partial,
                            rule="rule-c",
                            path="c.py",
                            snippet="bad_c()",
                        ),
                    ]
                )
                db.add(
                    db_models.ScannerCoverageEntry(
                        id=uuid4(),
                        scan_id=current.id,
                        attempt_id=current.current_attempt_id,
                        tenant_id=tenant.id,
                        scanner_name="semgrep",
                        input_path=".",
                        status="completed",
                        finding_count=7,
                    )
                )
                await db.flush()

                repo = FindingGovernanceRepository(db)
                records = await repo.materialize_scan(current.id, commit=False)
                self.assertEqual(
                    {row.baseline_state for row in records},
                    {"new", "fixed", "unchanged", "reintroduced"},
                )
                self.assertTrue(
                    all(row.attempt_id == current.current_attempt_id for row in records)
                )
                reintroduced = next(
                    row for row in records if row.baseline_state == "reintroduced"
                )
                self.assertEqual(
                    reintroduced.source_provenance["scanner_rule_id"], "rule-a"
                )
                self.assertEqual(reintroduced.exact_ranges[0]["start_line"], 10)
                repeated_sites = [
                    row
                    for row in records
                    if row.source_provenance["scanner_rule_id"] == "rule-c"
                ]
                self.assertEqual(len(repeated_sites), 2)
                self.assertEqual(
                    {row.exact_ranges[0]["start_line"] for row in repeated_sites},
                    {10, 30},
                )
                self.assertTrue(
                    all(row.baseline_state == "new" for row in repeated_sites),
                    "failed/cancelled partial scans must not create reintroduced history",
                )
                expanded_occurrences = [
                    row
                    for row in records
                    if row.source_provenance["scanner_rule_id"] == "rule-e"
                ]
                self.assertEqual(
                    sorted(row.baseline_state for row in expanded_occurrences),
                    ["new", "unchanged"],
                )
                contracted_occurrences = [
                    row
                    for row in records
                    if row.source_provenance["scanner_rule_id"] == "rule-f"
                ]
                self.assertEqual(
                    sorted(row.baseline_state for row in contracted_occurrences),
                    ["fixed", "unchanged"],
                )
                self.assertEqual(len({row.site_identity for row in repeated_sites}), 2)
                self.assertTrue(
                    all(len(row.site_identity) == 64 for row in repeated_sites)
                )
                replaced_finding = await db.scalar(
                    select(db_models.Finding).where(
                        db_models.Finding.scan_id == current.id,
                        db_models.Finding.scanner_rule_id == "rule-c",
                        db_models.Finding.line_number == 30,
                    )
                )
                old_finding_id = replaced_finding.id
                await db.delete(replaced_finding)
                await db.flush()
                replacement = self.finding(
                    current,
                    rule="rule-c",
                    path="c.py",
                    snippet="bad_c()",
                    line_number=30,
                )
                db.add(replacement)
                await db.flush()
                self.assertNotEqual(replacement.id, old_finding_id)
                retried_records = await repo.materialize_scan(current.id, commit=False)
                retried_site = next(
                    row
                    for row in retried_records
                    if row.source_provenance["scanner_rule_id"] == "rule-c"
                    and row.exact_ranges[0]["start_line"] == 30
                )
                await db.refresh(retried_site)
                self.assertEqual(
                    retried_site.site_identity,
                    next(
                        row.site_identity
                        for row in repeated_sites
                        if row.exact_ranges[0]["start_line"] == 30
                    ),
                )
                self.assertEqual(retried_site.finding_id, replacement.id)
                self.assertEqual(len(retried_records), len(records))
                savepoint = await db.begin_nested()
                with self.assertRaises(DBAPIError):
                    await db.execute(
                        update(db_models.FindingLineageRecord)
                        .where(db_models.FindingLineageRecord.id == retried_site.id)
                        .values(exact_ranges=[])
                    )
                await savepoint.rollback()
                first_attempt_id = current.current_attempt_id
                restarted = await ScanAttemptRepository(db).create_restart(
                    current.id, actor_user_id=user.id, commit=False
                )
                db.add(
                    db_models.ScannerCoverageEntry(
                        id=uuid4(),
                        scan_id=current.id,
                        attempt_id=restarted.id,
                        tenant_id=tenant.id,
                        scanner_name="semgrep",
                        input_path=".",
                        status="completed",
                        finding_count=7,
                    )
                )
                await db.flush()
                current_attempt_records = await repo.materialize_scan(
                    current.id, commit=False
                )
                self.assertNotEqual(restarted.id, first_attempt_id)
                self.assertTrue(
                    all(row.attempt_id == restarted.id for row in current_attempt_records)
                )
                history = await repo.lineage_history_for_scan(current.id)
                self.assertEqual(
                    len(history), len(records) + len(current_attempt_records)
                )

                evaluation = await repo.evaluate_scan_policy(
                    current.id, commit=False, idempotent=True
                )
                self.assertEqual(evaluation.outcome, "fail")
                self.assertTrue(evaluation.coverage_complete)
                self.assertEqual(len(evaluation.blocking_fingerprints), 5)
                persisted = await db.scalar(
                    select(db_models.FindingPolicyEvaluation).where(
                        db_models.FindingPolicyEvaluation.id == evaluation.id
                    )
                )
                self.assertIsNotNone(persisted)
                retry = await repo.evaluate_scan_policy(
                    current.id, commit=False, idempotent=True
                )
                self.assertEqual(retry.id, evaluation.id)
                evaluation_count = await db.scalar(
                    select(func.count(db_models.FindingPolicyEvaluation.id)).where(
                        db_models.FindingPolicyEvaluation.scan_id == current.id,
                        db_models.FindingPolicyEvaluation.policy_version_id
                        == evaluation.policy_version_id,
                    )
                )
                self.assertEqual(evaluation_count, 1)

                current_finding = await db.scalar(
                    select(db_models.Finding).where(
                        db_models.Finding.scan_id == current.id,
                        db_models.Finding.scanner_rule_id == "rule-a",
                    )
                )
                waiver = await repo.grant_waiver(
                    scan=current,
                    finding=current_finding,
                    scope="fingerprint",
                    reason="Approved temporary exception.",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=2),
                    actor_user_id=user.id,
                    commit=False,
                )
                waived_evaluation = await repo.evaluate_scan_policy(
                    current.id, commit=False
                )
                self.assertEqual(len(waived_evaluation.waived_fingerprints), 1)
                self.assertEqual(len(waived_evaluation.blocking_fingerprints), 4)
                await repo.revoke_waiver(
                    waiver,
                    actor_user_id=user.id,
                    reason="Exception is no longer required.",
                    commit=False,
                )
                _, events = await repo.waiver_history(waiver.id, tenant_id=tenant.id)
                self.assertEqual(
                    [event.action for event in events], ["granted", "revoked"]
                )

                elapsed = db_models.FindingWaiver(
                    id=uuid4(),
                    tenant_id=tenant.id,
                    project_id=project.id,
                    scan_id=current.id,
                    finding_id=current_finding.id,
                    fingerprint="f" * 64,
                    scope="finding",
                    scope_value=str(current_finding.id),
                    reason="Short-lived test exception.",
                    expires_at=datetime.now(timezone.utc) - timedelta(days=1),
                    actor_user_id=user.id,
                    created_at=datetime.now(timezone.utc) - timedelta(days=2),
                )
                db.add(elapsed)
                await db.flush()
                db.add(
                    db_models.FindingWaiverEvent(
                        tenant_id=tenant.id,
                        waiver_id=elapsed.id,
                        action="granted",
                        actor_user_id=user.id,
                        reason=elapsed.reason,
                    )
                )
                await db.flush()
                self.assertEqual(
                    await repo.record_expired_waivers(
                        tenant_id=tenant.id, commit=False
                    ),
                    1,
                )
                self.assertEqual(
                    await repo.record_expired_waivers(
                        tenant_id=tenant.id, commit=False
                    ),
                    0,
                )
                await db.delete(current)
                await db.flush()
                tombstone = await db.get(
                    db_models.FindingLineageRecord, reintroduced.id
                )
                await db.refresh(tombstone)
                self.assertIsNone(tombstone.scan_id)
                self.assertIsNone(tombstone.finding_id)
                await db.rollback()
        finally:
            reset_principal(binding)


if __name__ == "__main__":
    unittest.main()
