"""End-to-end deterministic planning and REMEDIATE promotion contract."""

from __future__ import annotations

import unittest
from uuid import uuid4
from unittest.mock import AsyncMock, patch

import psycopg
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.graph import END, StateGraph
from psycopg.rows import dict_row
from sqlalchemy import delete, func, select, text

from app.config.config import settings
from app.core.schemas import FixResult, FixSuggestion, VulnerabilityFinding
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    FindingFixCandidate,
    Project,
    Scan,
    ScanEvent,
    SourceCodeFile,
    User,
)
from app.infrastructure.database.repositories.scan_artifact_repo import (
    ARTIFACT_TYPE_PATCH_PLAN,
    ScanArtifactRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.nodes.consolidate import consolidate_and_patch_node
from app.infrastructure.workflows.nodes.results import save_results_node
from app.infrastructure.workflows.nodes.verify import verify_patches_node
from app.infrastructure.workflows.checkpoint_serde import checkpoint_serializer
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.finding_lineage_identity import (
    anchor_fingerprint,
    canonical_finding_id,
    fix_candidate_id,
    patch_fingerprint,
    raw_finding_id,
)
from app.shared.lib.patch_planner import PatchValidationCheck, source_hash
from tests.integration.support import integration_test


async def clean_builtin_replay(_files, source):
    return (
        PatchValidationCheck(
            stage=f"{source}_security_replay",
            status="passed",
            tool=source,
            detail="Fixture replay passed.",
            return_code=0,
            duration_ms=1,
        ),
        [],
    )


@integration_test
class PatchPlanPromotionIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.checkpoint_thread_ids: list[str] = []
        safe_name = f"safe_{uuid4().hex}"
        self.source = f"from security import {safe_name}\nresult = danger(value)\n"
        self.replacement = (
            f"from security import {safe_name}\nresult = {safe_name}(value)\n"
        )
        self.snapshot_hash = source_hash(self.source)
        async with AsyncSessionLocal() as db:
            user = User(
                email=f"patch-promotion-{uuid4()}@example.invalid",
                hashed_password="not-a-real-password-hash",
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(user)
            await db.flush()
            project = Project(name=f"patch-promotion-{uuid4()}", user_id=user.id)
            db.add(project)
            await db.flush()
            scan = Scan(project_id=project.id, user_id=user.id, scan_type="REMEDIATE")
            db.add(scan)
            persisted_hashes = await ScanRepository(db).get_or_create_source_files(
                [
                    {
                        "path": "src/app.py",
                        "content": self.source,
                        "language": "python",
                    }
                ],
                commit=False,
            )
            self.assertEqual(persisted_hashes, [self.snapshot_hash])
            await db.commit()
            self.user_id = user.id
            self.project_id = project.id
            self.scan_id = scan.id

    async def asyncTearDown(self) -> None:
        async with AsyncSessionLocal() as db:
            for thread_id in self.checkpoint_thread_ids:
                for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
                    await db.execute(
                        text(f"DELETE FROM {table} WHERE thread_id = :thread_id"),
                        {"thread_id": thread_id},
                    )
            await ScanRepository(db).delete_project(self.project_id)
            await db.execute(delete(User).where(User.id == self.user_id))
            await db.commit()
        await engine.dispose()

    def _aggregate(
        self,
        *,
        file_path: str = "src/app.py",
        source: str | None = None,
        replacement: str | None = None,
        index: int = 0,
    ) -> tuple[VulnerabilityFinding, FixResult]:
        source = source or self.source
        replacement = replacement or self.replacement
        snapshot_hash = source_hash(source)
        raw_id = raw_finding_id(self.scan_id, "promotion-test", index)
        canonical_id = canonical_finding_id([raw_id])
        finding = VulnerabilityFinding(
            raw_finding_id=raw_id,
            canonical_finding_id=canonical_id,
            contributing_raw_finding_ids=[raw_id],
            source_snapshot_hash=snapshot_hash,
            title="Unsafe call",
            description="Unsafe call",
            severity="High",
            line_number=1,
            remediation="Use safe",
            confidence="High",
            references=[],
            file_path=file_path,
            source="semgrep",
            scanner_rule_id="rules.danger",
        )
        suggestion = FixSuggestion(
            description="Use safe",
            original_snippet=source,
            code=replacement,
        )
        anchor = anchor_fingerprint(
            file_path=finding.file_path,
            source_snapshot_hash=snapshot_hash,
            line_number=1,
            original_snippet=source,
        )
        patch = patch_fingerprint(anchor=anchor, replacement_code=replacement)
        finding.fixes = suggestion
        candidate = FixResult(
            finding=finding,
            suggestion=suggestion,
            candidate_id=fix_candidate_id(raw_id=raw_id, patch=patch),
            raw_finding_id=raw_id,
            canonical_finding_id=canonical_id,
            source_snapshot_hash=snapshot_hash,
            anchor_fingerprint=anchor,
            patch_fingerprint=patch,
            disposition="selected",
            validation_status="passed",
        )
        return finding, candidate

    async def test_plan_promotes_exact_hunk_and_persists_artifact(self) -> None:
        finding, candidate = self._aggregate()
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {"src/app.py": self.source},
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay passed.",
            return_code=0,
            duration_ms=1,
        )
        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(return_value=(replay_pass, [])),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=clean_builtin_replay,
        ):
            candidate.validation_status = "not_run"
            verified = await verify_patches_node({**state, **planned})
        planned = {**planned, **verified}
        self.assertEqual(planned["patched_files"]["src/app.py"], self.replacement)
        self.assertTrue(candidate.is_applied)
        self.assertEqual(candidate.validation_status, "passed")
        self.assertEqual(candidate.applicability_status, "planned")
        self.assertIsNotNone(candidate.patch_hunk_id)
        self.assertEqual(
            planned["patch_validation_summary"]["outcome"],
            "remediation_validated",
        )
        self.assertEqual(
            planned["patch_plan"]["files"][0]["validation_checks"][0]["status"],
            "passed",
        )

        final_state = {**state, **planned}
        await save_results_node(final_state)
        async with AsyncSessionLocal() as db:
            artifact = await ScanArtifactRepository(db).get_by_type(
                self.scan_id, ARTIFACT_TYPE_PATCH_PLAN
            )
            patched_hash = planned["final_file_map"]["src/app.py"]
            patched_source = await db.scalar(
                select(SourceCodeFile.content).where(
                    SourceCodeFile.hash == patched_hash
                )
            )
            validation_event = await db.scalar(
                select(ScanEvent)
                .where(
                    ScanEvent.scan_id == self.scan_id,
                    ScanEvent.stage_name == "PATCH_VALIDATION",
                )
                .order_by(ScanEvent.id.desc())
            )
            persisted_candidate = await db.scalar(
                select(FindingFixCandidate).where(
                    FindingFixCandidate.candidate_id == candidate.candidate_id
                )
            )

        self.assertEqual(patched_source, self.replacement)
        self.assertEqual(
            artifact.payload["files"][0]["hunks"][0]["candidate_ids"],
            [str(candidate.candidate_id)],
        )
        self.assertIn("--- a/src/app.py", artifact.payload["files"][0]["unified_diff"])
        self.assertEqual(
            validation_event.details["candidates"]["applied"],
            1,
        )
        self.assertIsNotNone(persisted_candidate)
        self.assertEqual(persisted_candidate.validation_status, "passed")

    async def test_persistent_originating_rule_blocks_blob_and_snapshot_promotion(
        self,
    ) -> None:
        finding, candidate = self._aggregate()
        finding.source = "semgrep"
        finding.scanner_rule_id = "rules.danger"
        candidate.finding.source = "semgrep"
        candidate.finding.scanner_rule_id = "rules.danger"
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {"src/app.py": self.source},
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay completed.",
            return_code=0,
            duration_ms=1,
        )
        persistent = finding.model_copy(deep=True)
        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(return_value=(replay_pass, [persistent])),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=clean_builtin_replay,
        ):
            verified = await verify_patches_node({**state, **planned})

        self.assertIsNone(verified["final_file_map"])
        self.assertEqual(verified["patched_files"], {})
        self.assertFalse(candidate.is_applied)
        self.assertEqual(candidate.applicability_status, "validation_failed")
        replay_checks = verified["patch_plan"]["files"][0]["validation_checks"]
        semgrep_check = next(
            check
            for check in replay_checks
            if check["stage"] == "semgrep_security_replay"
        )
        self.assertEqual(semgrep_check["status"], "failed")
        async with AsyncSessionLocal() as db:
            broken_blob = await db.scalar(
                select(SourceCodeFile.hash).where(
                    SourceCodeFile.content == self.replacement
                )
            )
        self.assertIsNone(broken_blob)

    async def test_persistent_gitleaks_rule_is_a_pre_promotion_failure(self) -> None:
        finding, candidate = self._aggregate()
        finding.source = "gitleaks"
        finding.scanner_rule_id = "generic-api-key"
        candidate.finding = finding
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {"src/app.py": self.source},
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay completed.",
            return_code=0,
            duration_ms=1,
        )

        async def builtin_replay(_files, source):
            check = PatchValidationCheck(
                stage=f"{source}_security_replay",
                status="passed",
                tool=source,
                detail="Fixture replay completed.",
                return_code=0,
                duration_ms=1,
            )
            findings = [finding.model_copy(deep=True)] if source == "gitleaks" else []
            return check, findings

        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(return_value=(replay_pass, [])),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=builtin_replay,
        ):
            verified = await verify_patches_node({**state, **planned})

        self.assertIsNone(verified["final_file_map"])
        self.assertFalse(candidate.is_applied)
        self.assertEqual(candidate.applicability_status, "validation_failed")
        checks = verified["patch_plan"]["files"][0]["validation_checks"]
        gitleaks_check = next(
            check for check in checks if check["stage"] == "gitleaks_security_replay"
        )
        self.assertEqual(gitleaks_check["status"], "failed")

    async def test_new_bandit_finding_blocks_an_llm_originated_patch(self) -> None:
        finding, candidate = self._aggregate()
        finding.source = None
        finding.scanner_rule_id = None
        candidate.finding = finding
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {"src/app.py": self.source},
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay completed.",
            return_code=0,
            duration_ms=1,
        )
        regression = finding.model_copy(deep=True)
        regression.source = "bandit"
        regression.scanner_rule_id = "B602"

        async def builtin_replay(_files, source):
            check = PatchValidationCheck(
                stage=f"{source}_security_replay",
                status="passed",
                tool=source,
                detail="Fixture replay completed.",
                return_code=0,
                duration_ms=1,
            )
            return check, [regression] if source == "bandit" else []

        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(return_value=(replay_pass, [])),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=builtin_replay,
        ):
            verified = await verify_patches_node({**state, **planned})

        self.assertIsNone(verified["final_file_map"])
        self.assertFalse(candidate.is_applied)
        checks = verified["patch_plan"]["files"][0]["validation_checks"]
        bandit_check = next(
            check for check in checks if check["stage"] == "bandit_security_replay"
        )
        self.assertEqual(bandit_check["status"], "failed")
        self.assertIn("newly introduced finding", bandit_check["detail"])

    async def test_llm_origin_requires_positive_evidence_before_promotion(
        self,
    ) -> None:
        finding, candidate = self._aggregate()
        finding.source = None
        finding.scanner_rule_id = None
        candidate.finding = finding
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {"src/app.py": self.source},
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay completed.",
            return_code=0,
            duration_ms=1,
        )
        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(return_value=(replay_pass, [])),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=clean_builtin_replay,
        ):
            verified = await verify_patches_node({**state, **planned})

        self.assertIsNone(verified["final_file_map"])
        self.assertFalse(candidate.is_applied)
        self.assertEqual(candidate.applicability_status, "validation_unavailable")
        check = next(
            check
            for check in verified["patch_plan"]["files"][0]["validation_checks"]
            if check["stage"] == "llm_evidence_reanalysis"
        )
        self.assertEqual(check["status"], "tool_missing")
        self.assertTrue(check["blocking"])

    async def test_positive_llm_evidence_verdict_allows_promotion(self) -> None:
        finding, candidate = self._aggregate()
        finding.source = None
        finding.scanner_rule_id = None
        candidate.finding = finding
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "reasoning_llm_config_id": uuid4(),
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {"src/app.py": self.source},
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay completed.",
            return_code=0,
            duration_ms=1,
        )
        evidence_pass = PatchValidationCheck(
            stage="llm_evidence_reanalysis",
            status="passed",
            tool="reasoning-llm",
            detail="Fixture evidence directly supports resolution.",
            return_code=0,
            duration_ms=1,
            output='{"verdict":"resolved"}',
        )
        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(return_value=(replay_pass, [])),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=clean_builtin_replay,
        ), patch(
            "app.infrastructure.workflows.nodes.verify.create_patch_evidence_validator",
            new=AsyncMock(return_value=object()),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_llm_evidence_reanalysis",
            new=AsyncMock(return_value=evidence_pass),
        ):
            verified = await verify_patches_node({**state, **planned})

        self.assertEqual(verified["patched_files"]["src/app.py"], self.replacement)
        self.assertTrue(candidate.is_applied)
        check = next(
            check
            for check in verified["patch_plan"]["files"][0]["validation_checks"]
            if check["stage"] == "llm_evidence_reanalysis"
        )
        self.assertEqual(check["status"], "passed")

    async def test_suggest_and_remediate_share_full_validation_artifact(self) -> None:
        finding, candidate = self._aggregate()
        finding.source = None
        finding.scanner_rule_id = None
        candidate.finding = finding
        reasoning_config_id = uuid4()
        base_state = {
            "scan_id": self.scan_id,
            "reasoning_llm_config_id": reasoning_config_id,
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {"src/app.py": self.source},
            "_batch": 1,
        }
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay completed.",
            return_code=0,
            duration_ms=1,
        )
        evidence_pass = PatchValidationCheck(
            stage="llm_evidence_reanalysis",
            status="passed",
            tool="reasoning-llm",
            detail="Fixture evidence directly supports resolution.",
            return_code=0,
            duration_ms=1,
            output='{"verdict":"resolved"}',
        )
        sandbox_pass = PatchValidationCheck(
            stage="python_compile",
            status="passed",
            tool="python",
            detail="Fixture compiler completed.",
            return_code=0,
            duration_ms=1,
        )

        async def run(scan_type: str):
            run_finding = finding.model_copy(deep=True)
            run_candidate = candidate.model_copy(deep=True)
            run_candidate.finding = run_finding
            state = {
                **base_state,
                "scan_type": scan_type,
                "findings": [run_finding],
                "fix_candidates": [run_candidate],
            }
            with (
                patch(
                    "app.infrastructure.workflows.nodes.consolidate.run_sandbox_validation",
                    new=AsyncMock(return_value=[sandbox_pass.model_copy(deep=True)]),
                ),
                patch(
                    "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
                    new=AsyncMock(return_value=(replay_pass.model_copy(deep=True), [])),
                ),
                patch(
                    "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
                    new=clean_builtin_replay,
                ),
                patch(
                    "app.infrastructure.workflows.nodes.verify.create_patch_evidence_validator",
                    new=AsyncMock(return_value=object()),
                ),
                patch(
                    "app.infrastructure.workflows.nodes.verify._run_llm_evidence_reanalysis",
                    new=AsyncMock(return_value=evidence_pass.model_copy(deep=True)),
                ),
            ):
                planned = await consolidate_and_patch_node(state)
                verified = await verify_patches_node({**state, **planned})
            return run_candidate, verified

        suggested_candidate, suggested = await run("SUGGEST")
        remediated_candidate, remediated = await run("REMEDIATE")

        self.assertEqual(suggested["patch_plan"], remediated["patch_plan"])
        self.assertFalse(suggested_candidate.is_applied)
        self.assertNotIn("final_file_map", suggested)
        self.assertEqual(suggested["patched_files"], {})
        self.assertTrue(remediated_candidate.is_applied)
        self.assertEqual(remediated["patched_files"]["src/app.py"], self.replacement)
        self.assertIn("src/app.py", remediated["final_file_map"])

    async def test_file_atomicity_promotes_pass_and_rolls_back_failure(self) -> None:
        second_safe = f"safe_{uuid4().hex}"
        second_source = f"from security import {second_safe}\nother = danger(value)\n"
        second_replacement = (
            f"from security import {second_safe}\nother = {second_safe}(value)\n"
        )
        second_hash = source_hash(second_source)
        async with AsyncSessionLocal() as db:
            hashes = await ScanRepository(db).get_or_create_source_files(
                [
                    {
                        "path": "src/other.py",
                        "content": second_source,
                        "language": "python",
                    }
                ]
            )
        self.assertEqual(hashes, [second_hash])

        first_finding, first_candidate = self._aggregate(index=0)
        second_finding, second_candidate = self._aggregate(
            file_path="src/other.py",
            source=second_source,
            replacement=second_replacement,
            index=1,
        )
        for item in (first_finding, second_finding):
            item.source = "semgrep"
            item.scanner_rule_id = "rules.danger"
        first_candidate.finding = first_finding
        second_candidate.finding = second_finding
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {
                "src/app.py": self.snapshot_hash,
                "src/other.py": second_hash,
            },
            "live_codebase": {
                "src/app.py": self.source,
                "src/other.py": second_source,
            },
            "findings": [first_finding, second_finding],
            "fix_candidates": [first_candidate, second_candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay completed.",
            return_code=0,
            duration_ms=1,
        )
        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(
                side_effect=[
                    (replay_pass.model_copy(deep=True), []),
                    (
                        replay_pass.model_copy(deep=True),
                        [second_finding.model_copy(deep=True)],
                    ),
                ]
            ),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=clean_builtin_replay,
        ):
            verified = await verify_patches_node({**state, **planned})

        self.assertEqual(
            verified["patch_validation_summary"]["outcome"],
            "partial_remediation",
        )
        self.assertTrue(first_candidate.is_applied)
        self.assertFalse(second_candidate.is_applied)
        self.assertNotEqual(
            verified["final_file_map"]["src/app.py"], self.snapshot_hash
        )
        self.assertEqual(verified["final_file_map"]["src/other.py"], second_hash)
        async with AsyncSessionLocal() as db:
            broken_blob = await db.scalar(
                select(SourceCodeFile.hash).where(
                    SourceCodeFile.content == second_replacement
                )
            )
        self.assertIsNone(broken_blob)

    async def test_existing_manifest_dependency_allows_validated_promotion(
        self,
    ) -> None:
        finding, candidate = self._aggregate()
        candidate.language = "python"
        candidate.required_dependencies = ["secure-runtime>=2"]
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {
                "src/app.py": self.source,
                "pyproject.toml": (
                    "[project]\n"
                    'name = "fixture"\n'
                    'version = "1.0.0"\n'
                    'dependencies = ["secure-runtime>=2,<3"]\n'
                ),
            },
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        requirement_check = next(
            check
            for check in planned["patch_plan"]["files"][0]["validation_checks"]
            if check["stage"] == "dependency_requirements"
        )
        self.assertEqual(requirement_check["status"], "passed")
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay passed.",
            return_code=0,
            duration_ms=1,
        )
        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(return_value=(replay_pass, [])),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=clean_builtin_replay,
        ):
            verified = await verify_patches_node({**state, **planned})

        self.assertEqual(verified["patched_files"]["src/app.py"], self.replacement)
        self.assertTrue(candidate.is_applied)

    async def test_local_import_and_export_evidence_allows_validated_promotion(
        self,
    ) -> None:
        source = "result = danger(value)\n"
        replacement = "result = safe(value)\n"
        finding, candidate = self._aggregate(source=source, replacement=replacement)
        candidate.language = "python"
        candidate.required_imports = ["from security import safe"]
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {"src/app.py": source_hash(source)},
            "live_codebase": {
                "src/app.py": source,
                "src/security.py": "def safe(value):\n    return value\n",
            },
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        file_plan = planned["patch_plan"]["files"][0]
        import_check = next(
            check
            for check in file_plan["validation_checks"]
            if check["stage"] == "import_requirements"
        )
        self.assertEqual(import_check["status"], "passed")
        self.assertEqual(len(file_plan["hunks"]), 2)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay passed.",
            return_code=0,
            duration_ms=1,
        )
        with patch(
            "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
            new=AsyncMock(return_value=(replay_pass, [])),
        ), patch(
            "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
            new=clean_builtin_replay,
        ):
            verified = await verify_patches_node({**state, **planned})

        self.assertEqual(
            verified["patched_files"]["src/app.py"],
            "from security import safe\nresult = safe(value)\n",
        )
        self.assertTrue(candidate.is_applied)

    async def test_postgres_checkpoint_restart_runs_validation_and_promotion_once(
        self,
    ) -> None:
        """A worker restart resumes the pending gate without replaying it later."""
        finding, candidate = self._aggregate()
        state = {
            "scan_id": self.scan_id,
            "scan_type": "REMEDIATE",
            "initial_file_map": {"src/app.py": self.snapshot_hash},
            "live_codebase": {"src/app.py": self.source},
            "findings": [finding],
            "fix_candidates": [candidate],
            "_batch": 1,
        }
        planned = await consolidate_and_patch_node(state)
        replay_pass = PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail="Fixture replay passed.",
            return_code=0,
            duration_ms=1,
        )
        calls = 0

        async def should_not_run(_state):
            raise AssertionError("the completed planner checkpoint was replayed")

        async def counted_verify(graph_state):
            nonlocal calls
            calls += 1
            return await verify_patches_node(graph_state)

        graph = StateGraph(WorkerState)
        graph.add_node("consolidate_and_patch", should_not_run)
        graph.add_node("verify_patches", counted_verify)
        graph.set_entry_point("consolidate_and_patch")
        graph.add_edge("consolidate_and_patch", "verify_patches")
        graph.add_edge("verify_patches", END)

        thread_id = f"patch-validation-resume-{uuid4()}"
        self.checkpoint_thread_ids.append(thread_id)
        config = {"configurable": {"thread_id": thread_id}}
        conn_url = settings.ASYNC_DATABASE_URL.replace(
            "postgresql+asyncpg://", "postgresql://"
        )

        first_conn = await psycopg.AsyncConnection.connect(
            conn_url,
            autocommit=True,
            prepare_threshold=0,
            row_factory=dict_row,
        )
        try:
            first_worker = graph.compile(
                checkpointer=AsyncPostgresSaver(
                    conn=first_conn,
                    serde=checkpoint_serializer(),
                )
            )
            await first_worker.aupdate_state(
                config,
                {**state, **planned},
                as_node="consolidate_and_patch",
            )
        finally:
            await first_conn.close()

        second_conn = await psycopg.AsyncConnection.connect(
            conn_url,
            autocommit=True,
            prepare_threshold=0,
            row_factory=dict_row,
        )
        try:
            restarted_worker = graph.compile(
                checkpointer=AsyncPostgresSaver(
                    conn=second_conn,
                    serde=checkpoint_serializer(),
                )
            )
            with patch(
                "app.infrastructure.workflows.nodes.verify._run_semgrep_replay",
                new=AsyncMock(return_value=(replay_pass, [])),
            ), patch(
                "app.infrastructure.workflows.nodes.verify._run_builtin_scanner_replay",
                new=clean_builtin_replay,
            ):
                resumed = await restarted_worker.ainvoke(None, config)
        finally:
            await second_conn.close()

        third_conn = await psycopg.AsyncConnection.connect(
            conn_url,
            autocommit=True,
            prepare_threshold=0,
            row_factory=dict_row,
        )
        try:
            duplicate_worker = graph.compile(
                checkpointer=AsyncPostgresSaver(
                    conn=third_conn,
                    serde=checkpoint_serializer(),
                )
            )
            duplicate = await duplicate_worker.ainvoke(None, config)
        finally:
            await third_conn.close()

        self.assertEqual(calls, 1)
        self.assertEqual(resumed["final_file_map"], duplicate["final_file_map"])
        self.assertEqual(
            resumed["patch_validation_summary"],
            duplicate["patch_validation_summary"],
        )
        async with AsyncSessionLocal() as db:
            event_count = await db.scalar(
                select(func.count(ScanEvent.id)).where(
                    ScanEvent.scan_id == self.scan_id,
                    ScanEvent.stage_name == "PATCH_VERIFICATION",
                )
            )
            promoted_blob_count = await db.scalar(
                select(func.count(SourceCodeFile.hash)).where(
                    SourceCodeFile.content == self.replacement
                )
            )
        self.assertEqual(event_count, 1)
        self.assertEqual(promoted_blob_count, 1)


if __name__ == "__main__":
    unittest.main()
