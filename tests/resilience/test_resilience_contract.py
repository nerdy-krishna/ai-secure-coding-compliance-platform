from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from app.shared.lib.resilience_contract import (
    CONCURRENT_TENANTS,
    FAILURE_EXPECTATIONS,
    REQUIRED_RECOVERY_CHECKS,
    WORKLOADS,
    CapacityCoverage,
    CapacityRun,
    FailureRun,
    FailureScenario,
    LatencySamples,
    ProviderMode,
    RecoveryCheck,
    RecoveryMeasurements,
    RecoveryRun,
    ResilienceEvidenceSuite,
    RunIdentity,
    SaturationObservations,
    WorkloadProfile,
    evaluate_suite,
)


ROOT = Path(__file__).resolve().parents[2]


def _identity(run_id: str) -> RunIdentity:
    started = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
    return RunIdentity(
        run_id=run_id,
        environment="isolated-production-sized-cluster",
        git_commit="a" * 40,
        api_image_digest="sha256:" + "b" * 64,
        worker_image_digest="sha256:" + "c" * 64,
        chart_version="0.1.0",
        started_at=started,
        completed_at=started + timedelta(minutes=10),
        evidence_ref=f"s3://resilience-evidence/{run_id}/",
    )


def _latencies() -> LatencySamples:
    return LatencySamples(
        accepted_persistence_seconds=[0.5, 1.0, 1.5],
        queue_to_start_seconds=[1.0, 10.0, 100.0],
        approval_resume_seconds=[1.0, 5.0, 30.0],
        sse_freshness_seconds=[0.5, 1.0, 3.0],
        terminal_successes=100,
        terminal_eligible=100,
    )


def _saturation(tenants: int) -> SaturationObservations:
    return SaturationObservations(
        process_oom_kills=0,
        pod_oom_kills=0,
        queue_capacity_messages=100_000,
        queue_depth_start=0,
        queue_depth_peak=10_000,
        queue_depth_after_drain=0,
        storage_growth_bytes=1_000_000,
        storage_growth_budget_bytes=2_000_000,
        tenant_progress_units={f"tenant-{index}": 10 for index in range(tenants)},
    )


def _capacity(
    profile: WorkloadProfile,
    tenants: int,
    *,
    mode: ProviderMode = ProviderMode.DETERMINISTIC_FIXTURE,
) -> CapacityRun:
    file_count, total_bytes = WORKLOADS[profile]
    suffix = "live" if mode == ProviderMode.LIVE_BUDGETED_SMOKE else "fixture"
    return CapacityRun(
        identity=_identity(f"{profile.value}-{tenants}-{suffix}"),
        profile=profile,
        concurrent_tenants=tenants,
        file_count=file_count,
        total_uncompressed_bytes=total_bytes,
        provider_mode=mode,
        production_sizing_ref="git://deploy/production-sizing.yaml@sha256:measured",
        latencies=_latencies(),
        saturation=_saturation(tenants),
        coverage=CapacityCoverage(
            event_replay_operations=tenants,
            artifact_download_operations=tenants,
            artifact_download_digest_failures=0,
            deterministic_scanner_fixture=True,
            deterministic_provider_fixture=(mode == ProviderMode.DETERMINISTIC_FIXTURE),
        ),
        live_provider_budget_usd=(
            5.0 if mode == ProviderMode.LIVE_BUDGETED_SMOKE else None
        ),
        live_provider_actual_usd=(
            1.0 if mode == ProviderMode.LIVE_BUDGETED_SMOKE else None
        ),
    )


def _recovery() -> RecoveryRun:
    return RecoveryRun(
        identity=_identity("isolated-restore"),
        isolated_environment_ref="kubernetes://sccap-restore-20260824",
        governance_operation_id="0198f95a-restore-operation",
        governance_manifest_sha256="d" * 64,
        measurements=RecoveryMeasurements(
            postgres_data_loss_seconds=60,
            checkpoint_data_loss_seconds=60,
            configuration_data_loss_seconds=60,
            object_evidence_data_loss_seconds=600,
            vector_evidence_data_loss_seconds=600,
            acknowledged_rabbitmq_messages_lost=0,
            api_recovery_seconds=600,
            scan_resumption_seconds=900,
            analytics_recovery_seconds=3_600,
            search_recovery_seconds=3_600,
        ),
        checks=[
            RecoveryCheck(
                check_id=check_id,
                passed=True,
                evidence_ref=f"s3://resilience-evidence/restore/{check_id}.json",
            )
            for check_id in sorted(REQUIRED_RECOVERY_CHECKS)
        ],
    )


def _suite() -> ResilienceEvidenceSuite:
    capacity_runs = [
        _capacity(profile, tenants)
        for profile in WorkloadProfile
        for tenants in CONCURRENT_TENANTS
    ]
    capacity_runs.append(
        _capacity(
            WorkloadProfile.SMALL,
            1,
            mode=ProviderMode.LIVE_BUDGETED_SMOKE,
        )
    )
    return ResilienceEvidenceSuite(
        schema_version=1,
        capacity_runs=capacity_runs,
        failure_runs=[
            FailureRun(
                identity=_identity(f"failure-{index}"),
                scenario=scenario,
                injected_at_ref=f"s3://resilience-evidence/failures/{scenario}/inject.json",
                expected_degradation=FAILURE_EXPECTATIONS[scenario],
                observed_degradation=FAILURE_EXPECTATIONS[scenario],
                authorization_preserved=True,
                idempotency_preserved=True,
                durable_work_preserved=True,
                explicit_degraded_state=True,
                recovered=True,
            )
            for index, scenario in enumerate(FailureScenario)
        ],
        recovery_run=_recovery(),
    )


class ResilienceAcceptanceTests(unittest.TestCase):
    def test_complete_contract_fixture_passes(self) -> None:
        result = evaluate_suite(_suite())

        self.assertTrue(result.passed, result.failures)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.observations["maximum_50_jain_fairness"], 1.0)

    def test_slo_saturation_rpo_rto_and_recovery_fail_closed(self) -> None:
        suite = _suite()
        representative = next(
            run
            for run in suite.capacity_runs
            if run.provider_mode == ProviderMode.DETERMINISTIC_FIXTURE
            and run.profile == WorkloadProfile.REPRESENTATIVE
            and run.concurrent_tenants == 10
        )
        representative.latencies.accepted_persistence_seconds = [2.0]
        maximum = next(
            run
            for run in suite.capacity_runs
            if run.provider_mode == ProviderMode.DETERMINISTIC_FIXTURE
            and run.profile == WorkloadProfile.MAXIMUM
            and run.concurrent_tenants == 50
        )
        maximum.saturation.pod_oom_kills = 1
        maximum.saturation.tenant_progress_units["tenant-0"] = 0
        suite.recovery_run.measurements.postgres_data_loss_seconds = 301
        suite.recovery_run.measurements.api_recovery_seconds = 3_601
        suite.recovery_run.checks[0].passed = False

        result = evaluate_suite(suite)

        self.assertFalse(result.passed)
        rendered = "\n".join(result.failures)
        self.assertIn("Task21 SLO failed", rendered)
        self.assertIn("OOM", rendered)
        self.assertIn("starved", rendered)
        self.assertIn("RPO failed", rendered)
        self.assertIn("RTO failed", rendered)
        self.assertIn("failed recovery checks", rendered)

    def test_missing_runs_and_failure_scenarios_are_rejected(self) -> None:
        suite = _suite()
        suite.capacity_runs = suite.capacity_runs[-1:]
        suite.failure_runs = []

        result = evaluate_suite(suite)

        self.assertFalse(result.passed)
        self.assertTrue(
            any(
                "missing deterministic capacity runs" in item
                for item in result.failures
            )
        )
        self.assertTrue(
            any("missing failure scenarios" in item for item in result.failures)
        )

    def test_unknown_fields_and_duplicate_scenarios_fail_schema_validation(
        self,
    ) -> None:
        payload = _suite().model_dump(mode="json")
        payload["unreviewed_override"] = True
        with self.assertRaises(ValidationError):
            ResilienceEvidenceSuite.model_validate(payload)

        suite = _suite()
        suite.failure_runs.append(suite.failure_runs[0].model_copy(deep=True))
        with self.assertRaises(ValidationError):
            ResilienceEvidenceSuite.model_validate(suite.model_dump(mode="json"))

    def test_catalog_is_synchronized_with_executable_contract(self) -> None:
        catalog = json.loads(
            (ROOT / "deploy/resilience/scenario-catalog.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(catalog["capacity"]["concurrent_tenants"], [1, 10, 50])
        self.assertEqual(
            {
                item["name"]: (item["file_count"], item["uncompressed_bytes"])
                for item in catalog["capacity"]["profiles"]
            },
            {profile.value: values for profile, values in WORKLOADS.items()},
        )
        self.assertEqual(
            {item["scenario"]: item["expected"] for item in catalog["failures"]},
            {
                scenario.value: expected
                for scenario, expected in FAILURE_EXPECTATIONS.items()
            },
        )


class DeterministicFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = ROOT / "scripts/resilience/generate_workload.py"
        spec = importlib.util.spec_from_file_location("generate_workload", path)
        assert spec is not None and spec.loader is not None
        cls.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.generator)

    def test_fixture_is_exact_and_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            first = Path(temporary_directory) / "first.zip"
            second = Path(temporary_directory) / "second.zip"
            with patch.dict(
                self.generator.WORKLOADS,
                {WorkloadProfile.SMALL: (3, 300)},
            ):
                first_manifest = self.generator.generate_archive(
                    WorkloadProfile.SMALL, first, force=False
                )
                second_manifest = self.generator.generate_archive(
                    WorkloadProfile.SMALL, second, force=False
                )

            self.assertEqual(first_manifest["file_count"], 3)
            self.assertEqual(first_manifest["total_uncompressed_bytes"], 300)
            self.assertEqual(
                first_manifest["content_stream_sha256"],
                second_manifest["content_stream_sha256"],
            )
            self.assertEqual(
                first_manifest["archive_sha256"], second_manifest["archive_sha256"]
            )

    def test_fixture_refuses_implicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "fixture.zip"
            output.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                self.generator.generate_archive(
                    WorkloadProfile.SMALL, output, force=False
                )


if __name__ == "__main__":
    unittest.main()
