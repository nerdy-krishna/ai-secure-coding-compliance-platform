"""Machine-readable acceptance contract for Task 24 resilience evidence.

This module deliberately evaluates evidence; it does not manufacture performance
or recovery results.  Cluster exercises write a JSON document containing raw
observations and evidence references, and :func:`evaluate_suite` applies the
approved workload, SLO, RPO, RTO, failure-matrix, and recovery rules.
"""

from __future__ import annotations

import math
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


MIB = 1024 * 1024


class WorkloadProfile(StrEnum):
    SMALL = "small"
    REPRESENTATIVE = "representative"
    MAXIMUM = "maximum"


WORKLOADS: dict[WorkloadProfile, tuple[int, int]] = {
    WorkloadProfile.SMALL: (100, 5 * MIB),
    WorkloadProfile.REPRESENTATIVE: (2_000, 100 * MIB),
    WorkloadProfile.MAXIMUM: (5_000, 200 * MIB),
}
CONCURRENT_TENANTS = (1, 10, 50)


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ProviderMode(StrEnum):
    DETERMINISTIC_FIXTURE = "deterministic_fixture"
    LIVE_BUDGETED_SMOKE = "live_budgeted_smoke"


class FailureScenario(StrEnum):
    POSTGRES_FAILOVER = "postgres_failover"
    RABBITMQ_RESTART = "rabbitmq_restart_redelivery"
    OBJECT_STORE_OUTAGE = "object_store_outage"
    OBJECT_STORE_CORRUPTION = "object_store_corruption"
    QDRANT_OUTAGE = "qdrant_outage"
    SCANNER_TIMEOUT = "scanner_timeout"
    SCANNER_CRASH = "scanner_crash"
    PROVIDER_429 = "provider_429"
    PROVIDER_5XX = "provider_5xx"
    PROVIDER_TIMEOUT = "provider_timeout"
    NODE_TERMINATION_PRESCAN_GATE = "node_termination_prescan_gate"
    NODE_TERMINATION_PROFILING_GATE = "node_termination_profiling_gate"
    NODE_TERMINATION_ANALYSIS_GATE = "node_termination_analysis_gate"
    NETWORK_PARTITION = "network_partition"


FAILURE_EXPECTATIONS: dict[FailureScenario, str] = {
    FailureScenario.POSTGRES_FAILOVER: "intake pauses; no stale-primary resume",
    FailureScenario.RABBITMQ_RESTART: "outbox accumulates then redelivers idempotently",
    FailureScenario.OBJECT_STORE_OUTAGE: "artifact operations fail explicitly and retry",
    FailureScenario.OBJECT_STORE_CORRUPTION: "digest verification fails closed",
    FailureScenario.QDRANT_OUTAGE: "RAG is explicitly degraded without cross-tenant fallback",
    FailureScenario.SCANNER_TIMEOUT: "scanner coverage is degraded, never reported verified",
    FailureScenario.SCANNER_CRASH: "scanner coverage is degraded, never reported verified",
    FailureScenario.PROVIDER_429: "bounded retry or circuit break preserves the attempt",
    FailureScenario.PROVIDER_5XX: "bounded retry or circuit break preserves the attempt",
    FailureScenario.PROVIDER_TIMEOUT: "bounded retry or circuit break preserves the attempt",
    FailureScenario.NODE_TERMINATION_PRESCAN_GATE: "same checkpoint and gate identity resumes",
    FailureScenario.NODE_TERMINATION_PROFILING_GATE: "same checkpoint and gate identity resumes",
    FailureScenario.NODE_TERMINATION_ANALYSIS_GATE: "same checkpoint and gate identity resumes",
    FailureScenario.NETWORK_PARTITION: "durable work waits without authorization bypass",
}


class RunIdentity(ContractModel):
    run_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    environment: Annotated[str, Field(min_length=1, max_length=120)]
    git_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    api_image_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    worker_image_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    chart_version: Annotated[str, Field(min_length=1, max_length=64)]
    started_at: datetime
    completed_at: datetime
    evidence_ref: Annotated[str, Field(min_length=1, max_length=2048)]

    @model_validator(mode="after")
    def completed_after_start(self) -> "RunIdentity":
        if self.started_at.utcoffset() is None or self.completed_at.utcoffset() is None:
            raise ValueError("run timestamps must include a UTC offset")
        if self.completed_at <= self.started_at:
            raise ValueError("completed_at must be after started_at")
        return self


class LatencySamples(ContractModel):
    accepted_persistence_seconds: list[Annotated[float, Field(ge=0)]]
    queue_to_start_seconds: list[Annotated[float, Field(ge=0)]]
    approval_resume_seconds: list[Annotated[float, Field(ge=0)]]
    sse_freshness_seconds: list[Annotated[float, Field(ge=0)]]
    terminal_successes: Annotated[int, Field(ge=0)]
    terminal_eligible: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def samples_are_present(self) -> "LatencySamples":
        for name in (
            "accepted_persistence_seconds",
            "queue_to_start_seconds",
            "approval_resume_seconds",
            "sse_freshness_seconds",
        ):
            if not getattr(self, name):
                raise ValueError(f"{name} must contain measured samples")
        if self.terminal_successes > self.terminal_eligible:
            raise ValueError("terminal_successes cannot exceed terminal_eligible")
        return self


class SaturationObservations(ContractModel):
    process_oom_kills: Annotated[int, Field(ge=0)]
    pod_oom_kills: Annotated[int, Field(ge=0)]
    queue_capacity_messages: Annotated[int, Field(gt=0)]
    queue_depth_start: Annotated[int, Field(ge=0)]
    queue_depth_peak: Annotated[int, Field(ge=0)]
    queue_depth_after_drain: Annotated[int, Field(ge=0)]
    storage_growth_bytes: Annotated[int, Field(ge=0)]
    storage_growth_budget_bytes: Annotated[int, Field(gt=0)]
    tenant_progress_units: dict[
        Annotated[str, Field(min_length=1, max_length=128)],
        Annotated[int, Field(ge=0)],
    ]


class CapacityCoverage(ContractModel):
    event_replay_operations: Annotated[int, Field(gt=0)]
    artifact_download_operations: Annotated[int, Field(gt=0)]
    artifact_download_digest_failures: Annotated[int, Field(ge=0)]
    deterministic_scanner_fixture: bool
    deterministic_provider_fixture: bool


class CapacityRun(ContractModel):
    identity: RunIdentity
    profile: WorkloadProfile
    concurrent_tenants: Literal[1, 10, 50]
    file_count: Annotated[int, Field(gt=0)]
    total_uncompressed_bytes: Annotated[int, Field(gt=0)]
    provider_mode: ProviderMode
    production_sizing_ref: Annotated[str, Field(min_length=1, max_length=2048)]
    latencies: LatencySamples
    saturation: SaturationObservations
    coverage: CapacityCoverage
    live_provider_budget_usd: Annotated[float | None, Field(gt=0)] = None
    live_provider_actual_usd: Annotated[float | None, Field(ge=0)] = None

    @model_validator(mode="after")
    def workload_matches_contract(self) -> "CapacityRun":
        expected_files, expected_bytes = WORKLOADS[self.profile]
        if (self.file_count, self.total_uncompressed_bytes) != (
            expected_files,
            expected_bytes,
        ):
            raise ValueError(
                f"{self.profile} must be {expected_files} files/{expected_bytes} bytes"
            )
        if len(self.saturation.tenant_progress_units) != self.concurrent_tenants:
            raise ValueError(
                "tenant progress must contain exactly one entry per tenant"
            )
        if self.provider_mode == ProviderMode.LIVE_BUDGETED_SMOKE:
            if self.live_provider_budget_usd is None:
                raise ValueError("live provider smoke requires a positive budget")
            if self.live_provider_actual_usd is None:
                raise ValueError("live provider smoke requires measured spend")
        elif (
            self.live_provider_budget_usd is not None
            or self.live_provider_actual_usd is not None
        ):
            raise ValueError("fixture runs must not claim live-provider spend")
        if self.provider_mode == ProviderMode.DETERMINISTIC_FIXTURE and not all(
            (
                self.coverage.deterministic_scanner_fixture,
                self.coverage.deterministic_provider_fixture,
            )
        ):
            raise ValueError(
                "deterministic capacity runs require scanner and provider fixtures"
            )
        return self


class FailureRun(ContractModel):
    identity: RunIdentity
    scenario: FailureScenario
    injected_at_ref: Annotated[str, Field(min_length=1, max_length=2048)]
    expected_degradation: Annotated[str, Field(min_length=1, max_length=2048)]
    observed_degradation: Annotated[str, Field(min_length=1, max_length=2048)]
    authorization_preserved: bool
    idempotency_preserved: bool
    durable_work_preserved: bool
    explicit_degraded_state: bool
    recovered: bool

    @model_validator(mode="after")
    def expectation_matches_catalog(self) -> "FailureRun":
        if self.expected_degradation != FAILURE_EXPECTATIONS[self.scenario]:
            raise ValueError("expected_degradation does not match the approved matrix")
        return self


class RecoveryMeasurements(ContractModel):
    postgres_data_loss_seconds: Annotated[float, Field(ge=0)]
    checkpoint_data_loss_seconds: Annotated[float, Field(ge=0)]
    configuration_data_loss_seconds: Annotated[float, Field(ge=0)]
    object_evidence_data_loss_seconds: Annotated[float, Field(ge=0)]
    vector_evidence_data_loss_seconds: Annotated[float, Field(ge=0)]
    acknowledged_rabbitmq_messages_lost: Annotated[int, Field(ge=0)]
    api_recovery_seconds: Annotated[float, Field(ge=0)]
    scan_resumption_seconds: Annotated[float, Field(ge=0)]
    analytics_recovery_seconds: Annotated[float, Field(ge=0)]
    search_recovery_seconds: Annotated[float, Field(ge=0)]


REQUIRED_RECOVERY_CHECKS = frozenset(
    {
        "transactional_data_restored",
        "checkpoint_threads_restored",
        "evidence_versions_and_keys_restored",
        "qdrant_collections_restored",
        "connector_configuration_restored",
        "policy_configuration_restored",
        "observability_context_restored",
        "governance_manifest_signature_verified",
        "governance_manifest_digest_verified",
        "runtime_role_has_no_bypassrls",
        "same_tenant_rls_probe_allowed",
        "cross_tenant_rls_probe_denied",
        "artifact_plaintext_and_ciphertext_digests_verified",
        "outbox_converged_without_duplicate_effects",
        "coverage_reports_degraded_dependencies_truthfully",
        "scan_attempt_and_checkpoint_identity_resumable",
        "approval_gates_not_repeated",
    }
)


class RecoveryCheck(ContractModel):
    check_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,95}$")]
    passed: bool
    evidence_ref: Annotated[str, Field(min_length=1, max_length=2048)]


class RecoveryRun(ContractModel):
    identity: RunIdentity
    isolated_environment_ref: Annotated[str, Field(min_length=1, max_length=2048)]
    governance_operation_id: Annotated[str, Field(min_length=1, max_length=128)]
    governance_manifest_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    measurements: RecoveryMeasurements
    checks: list[RecoveryCheck]

    @model_validator(mode="after")
    def checks_are_unique(self) -> "RecoveryRun":
        ids = [check.check_id for check in self.checks]
        if len(ids) != len(set(ids)):
            raise ValueError("recovery check IDs must be unique")
        return self


class ResilienceEvidenceSuite(ContractModel):
    schema_version: Literal[1]
    capacity_runs: list[CapacityRun]
    failure_runs: list[FailureRun]
    recovery_run: RecoveryRun

    @model_validator(mode="after")
    def run_identities_and_scenarios_are_unique(self) -> "ResilienceEvidenceSuite":
        run_ids = [run.identity.run_id for run in self.capacity_runs]
        run_ids.extend(run.identity.run_id for run in self.failure_runs)
        run_ids.append(self.recovery_run.identity.run_id)
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("run IDs must be unique across the evidence suite")

        fixture_keys = [
            (run.profile, run.concurrent_tenants)
            for run in self.capacity_runs
            if run.provider_mode == ProviderMode.DETERMINISTIC_FIXTURE
        ]
        if len(fixture_keys) != len(set(fixture_keys)):
            raise ValueError("deterministic workload/profile runs must be unique")

        scenarios = [run.scenario for run in self.failure_runs]
        if len(scenarios) != len(set(scenarios)):
            raise ValueError("failure scenarios must be unique")
        return self


class AcceptanceResult(ContractModel):
    passed: bool
    failures: list[str]
    observations: dict[str, float | int | str]


def _p95(samples: list[float]) -> float:
    """Nearest-rank p95, intentionally transparent for audit evidence."""

    ordered = sorted(samples)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def _jain_fairness(progress: list[int]) -> float:
    if not progress or sum(progress) == 0:
        return 0.0
    total = float(sum(progress))
    squares = float(sum(value * value for value in progress))
    return (total * total) / (len(progress) * squares)


def evaluate_suite(suite: ResilienceEvidenceSuite) -> AcceptanceResult:
    """Apply the approved Task24 decisions to measured evidence."""

    failures: list[str] = []
    observations: dict[str, float | int | str] = {}

    expected_matrix = {
        (profile, tenants)
        for profile in WorkloadProfile
        for tenants in CONCURRENT_TENANTS
    }
    fixture_runs = {
        (run.profile, run.concurrent_tenants): run
        for run in suite.capacity_runs
        if run.provider_mode == ProviderMode.DETERMINISTIC_FIXTURE
    }
    missing = sorted(
        expected_matrix - fixture_runs.keys(), key=lambda value: (value[0], value[1])
    )
    if missing:
        failures.append(
            "missing deterministic capacity runs: "
            + ", ".join(f"{profile}/{tenants}" for profile, tenants in missing)
        )

    live_runs = [
        run
        for run in suite.capacity_runs
        if run.provider_mode == ProviderMode.LIVE_BUDGETED_SMOKE
    ]
    if not live_runs:
        failures.append("missing separately budget-capped live-provider smoke")
    for run in live_runs:
        budget = run.live_provider_budget_usd
        actual = run.live_provider_actual_usd
        if budget is None or actual is None:
            failures.append(f"{run.identity.run_id}: live-provider spend is missing")
        elif actual > budget:
            failures.append(f"{run.identity.run_id}: live-provider budget exceeded")

    for run in suite.capacity_runs:
        if run.coverage.artifact_download_digest_failures:
            failures.append(f"{run.identity.run_id}: artifact download digest failed")

    representative = fixture_runs.get((WorkloadProfile.REPRESENTATIVE, 10))
    if representative is not None:
        slo_values = {
            "accepted_persistence_p95": _p95(
                representative.latencies.accepted_persistence_seconds
            ),
            "queue_to_start_p95": _p95(representative.latencies.queue_to_start_seconds),
            "approval_resume_p95": _p95(
                representative.latencies.approval_resume_seconds
            ),
            "sse_freshness_p95": _p95(representative.latencies.sse_freshness_seconds),
            "terminal_success_ratio": (
                representative.latencies.terminal_successes
                / representative.latencies.terminal_eligible
            ),
        }
        observations.update(slo_values)
        limits = {
            "accepted_persistence_p95": (2.0, "lt"),
            "queue_to_start_p95": (300.0, "lt"),
            "approval_resume_p95": (60.0, "lt"),
            "sse_freshness_p95": (5.0, "lt"),
            "terminal_success_ratio": (0.99, "gte"),
        }
        for metric, (limit, operator) in limits.items():
            value = slo_values[metric]
            breached = value >= limit if operator == "lt" else value < limit
            if breached:
                failures.append(
                    f"representative/10 Task21 SLO failed: {metric}={value}"
                )

    maximum_runs = [
        fixture_runs[(WorkloadProfile.MAXIMUM, tenants)]
        for tenants in CONCURRENT_TENANTS
        if (WorkloadProfile.MAXIMUM, tenants) in fixture_runs
    ]
    for maximum in maximum_runs:
        saturation = maximum.saturation
        progress = list(saturation.tenant_progress_units.values())
        fairness = _jain_fairness(progress)
        label = f"maximum/{maximum.concurrent_tenants}"
        observations[f"maximum_{maximum.concurrent_tenants}_jain_fairness"] = fairness
        if saturation.process_oom_kills or saturation.pod_oom_kills:
            failures.append(f"{label} observed an OOM kill")
        if saturation.queue_depth_peak > saturation.queue_capacity_messages:
            failures.append(f"{label} queue exceeded its declared bound")
        if saturation.queue_depth_after_drain > saturation.queue_depth_start:
            failures.append(f"{label} queue did not return to its pre-run bound")
        if saturation.storage_growth_bytes > saturation.storage_growth_budget_bytes:
            failures.append(f"{label} storage growth exceeded its declared bound")
        if any(value == 0 for value in progress):
            failures.append(f"{label} starved at least one tenant")
        if fairness < 0.90:
            failures.append(f"{label} tenant fairness below 0.90: {fairness:.4f}")

    failure_by_scenario = {run.scenario: run for run in suite.failure_runs}
    missing_failures = sorted(set(FailureScenario) - failure_by_scenario.keys())
    if missing_failures:
        failures.append("missing failure scenarios: " + ", ".join(missing_failures))
    for scenario, run in failure_by_scenario.items():
        if not all(
            (
                run.authorization_preserved,
                run.idempotency_preserved,
                run.durable_work_preserved,
                run.explicit_degraded_state,
                run.recovered,
            )
        ):
            failures.append(f"{scenario}: degradation/recovery contract failed")

    measurements = suite.recovery_run.measurements
    rpo_limits = {
        "postgres_data_loss_seconds": 300.0,
        "checkpoint_data_loss_seconds": 300.0,
        "configuration_data_loss_seconds": 300.0,
        "object_evidence_data_loss_seconds": 900.0,
        "vector_evidence_data_loss_seconds": 900.0,
    }
    for field, limit in rpo_limits.items():
        value = getattr(measurements, field)
        observations[field] = value
        if value > limit:
            failures.append(f"RPO failed: {field}={value}s exceeds {limit}s")
    if measurements.acknowledged_rabbitmq_messages_lost != 0:
        failures.append("RPO failed: acknowledged RabbitMQ messages were lost")

    rto_limits = {
        "api_recovery_seconds": 3_600.0,
        "scan_resumption_seconds": 3_600.0,
        "analytics_recovery_seconds": 14_400.0,
        "search_recovery_seconds": 14_400.0,
    }
    for field, limit in rto_limits.items():
        value = getattr(measurements, field)
        observations[field] = value
        if value > limit:
            failures.append(f"RTO failed: {field}={value}s exceeds {limit}s")

    checks = {check.check_id: check for check in suite.recovery_run.checks}
    missing_checks = sorted(REQUIRED_RECOVERY_CHECKS - checks.keys())
    if missing_checks:
        failures.append("missing recovery checks: " + ", ".join(missing_checks))
    failed_checks = sorted(
        check_id
        for check_id, check in checks.items()
        if check_id in REQUIRED_RECOVERY_CHECKS and not check.passed
    )
    if failed_checks:
        failures.append("failed recovery checks: " + ", ".join(failed_checks))

    return AcceptanceResult(
        passed=not failures,
        failures=failures,
        observations=observations,
    )
