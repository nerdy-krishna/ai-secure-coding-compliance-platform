"""Server-side sandbox fixture execution for Rule Foundry quality attestations."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import statistics
import tempfile
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, Mapping, Protocol

import yaml

from app.shared.lib.rule_foundry import QualityMetrics


class QualityEvaluationError(RuntimeError):
    pass


class CandidateQualityEvaluator(Protocol):
    async def evaluate(
        self,
        *,
        registry_kind: str,
        payload: Mapping[str, Any],
        fixtures: Mapping[str, Any],
    ) -> QualityMetrics: ...


class SandboxQualityEvaluator:
    """Runs candidate fixtures locally; callers supply a trusted baseline metric."""

    def __init__(self, *, baseline_median_ms: Decimal, timeout_seconds: int = 20) -> None:
        if baseline_median_ms <= 0:
            raise ValueError("Rule Foundry baseline median must be positive.")
        self.baseline_median_ms = baseline_median_ms
        self.timeout_seconds = timeout_seconds

    async def evaluate(
        self,
        *,
        registry_kind: str,
        payload: Mapping[str, Any],
        fixtures: Mapping[str, Any],
    ) -> QualityMetrics:
        run_outputs: list[dict[str, list[str]]] = []
        durations: list[Decimal] = []
        duplicate_count = 0
        for _run in range(3):
            output: dict[str, list[str]] = {}
            for category in ("vulnerable", "fixed", "negative", "performance", "churn"):
                for fixture in fixtures.get(category, []):
                    started = time.perf_counter_ns()
                    identities = await self._execute(registry_kind, payload, fixture)
                    elapsed_ms = Decimal(time.perf_counter_ns() - started) / Decimal(1_000_000)
                    durations.append(elapsed_ms)
                    key = f"{category}:{fixture['name']}"
                    output[key] = sorted(identities)
                    duplicate_count += len(identities) - len(set(identities))
            run_outputs.append(output)

        hashes = tuple(
            hashlib.sha256(
                json.dumps(output, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            for output in run_outputs
        )
        first = run_outputs[0]
        vulnerable = fixtures.get("vulnerable", [])
        fixed = fixtures.get("fixed", [])
        negative = fixtures.get("negative", [])
        churn = fixtures.get("churn", [])
        churn_stable = sum(
            1
            for fixture in churn
            if all(
                output.get(f"churn:{fixture['name']}") == first.get(f"churn:{fixture['name']}")
                for output in run_outputs[1:]
            )
        )
        sorted_durations = sorted(durations)
        p95_index = max(0, int(len(sorted_durations) * 0.95 + 0.9999) - 1)
        return QualityMetrics(
            vulnerable_total=len(vulnerable),
            vulnerable_detected=sum(
                bool(first.get(f"vulnerable:{item['name']}"))
                for item in vulnerable
            ),
            fixed_total=len(fixed),
            fixed_clean=sum(not first.get(f"fixed:{item['name']}") for item in fixed),
            negative_total=len(negative),
            negative_clean=sum(not first.get(f"negative:{item['name']}") for item in negative),
            duplicate_stable_identities=duplicate_count,
            deterministic_run_hashes=hashes,
            performance_fixture_count=len(fixtures.get("performance", [])),
            churn_fixture_count=len(churn),
            churn_stable=churn_stable,
            baseline_median_ms=self.baseline_median_ms,
            candidate_median_ms=Decimal(str(statistics.median(durations))),
            p95_file_ms=sorted_durations[p95_index],
        )

    async def _execute(
        self, registry_kind: str, payload: Mapping[str, Any], fixture: Mapping[str, Any]
    ) -> list[str]:
        if registry_kind == "semgrep":
            return await self._run_semgrep(payload, fixture)
        if registry_kind == "gitleaks":
            return await self._run_gitleaks(payload, fixture)
        if registry_kind == "osv":
            return self._evaluate_osv(payload, fixture)
        raise QualityEvaluationError(f"Unsupported registry: {registry_kind}")

    async def _run_semgrep(
        self, payload: Mapping[str, Any], fixture: Mapping[str, Any]
    ) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="sccap-rule-foundry-") as tmp:
            root = Path(tmp)
            suffix = _language_suffix(str(fixture["language"]))
            target = root / f"fixture{suffix}"
            target.write_text(str(fixture["content"]), encoding="utf-8")
            config = root / "rule.yaml"
            rule = dict(payload)
            config.write_text(yaml.safe_dump({"rules": [rule]}, sort_keys=True), encoding="utf-8")
            raw = await self._run_process(
                os.getenv("SEMGREP_BINARY", "/usr/local/bin/semgrep"),
                "--config",
                str(config),
                "--json",
                "--metrics=off",
                str(target),
            )
            try:
                result = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise QualityEvaluationError("Semgrep sandbox returned invalid JSON.") from exc
            if result.get("errors"):
                raise QualityEvaluationError("Semgrep rejected the candidate rule or fixture.")
            return [
                _match_identity(str(item.get("check_id", "")), item)
                for item in result.get("results", [])
            ]

    async def _run_gitleaks(
        self, payload: Mapping[str, Any], fixture: Mapping[str, Any]
    ) -> list[str]:
        required = ("id", "regex")
        if any(not str(payload.get(key, "")).strip() for key in required):
            raise QualityEvaluationError("Gitleaks rule requires id and regex.")
        with tempfile.TemporaryDirectory(prefix="sccap-rule-foundry-") as tmp:
            root = Path(tmp)
            source_root = root / "source"
            source_root.mkdir(mode=0o700)
            target = source_root / f"fixture{_language_suffix(str(fixture['language']))}"
            target.write_text(str(fixture["content"]), encoding="utf-8")
            report = root / "report.json"
            config = root / "gitleaks.toml"
            keywords = payload.get("keywords") or []
            toml = [
                "[[rules]]",
                f"id = {json.dumps(str(payload['id']))}",
                f"description = {json.dumps(str(payload.get('description') or payload['id']))}",
                f"regex = {json.dumps(str(payload['regex']))}",
            ]
            if payload.get("secret_group") is not None:
                toml.append(f"secretGroup = {int(payload['secret_group'])}")
            if keywords:
                toml.append(
                    "keywords = ["
                    + ",".join(json.dumps(str(v)) for v in keywords[:50])
                    + "]"
                )
            config.write_text("\n".join(toml) + "\n", encoding="utf-8")
            raw = await self._run_process(
                os.getenv("GITLEAKS_BINARY", "/usr/local/bin/gitleaks"),
                "detect",
                "--no-git",
                "--source",
                str(source_root),
                "--config",
                str(config),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                allow_nonzero=True,
            )
            del raw
            if not report.exists():
                return []
            try:
                findings = json.loads(report.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise QualityEvaluationError("Gitleaks sandbox returned invalid JSON.") from exc
            return [
                hashlib.sha256(
                    (
                        f"{item.get('RuleID')}:"
                        f"{Path(str(item.get('File', ''))).name}:"
                        f"{item.get('StartLine')}"
                    ).encode()
                ).hexdigest()
                for item in findings
            ]

    @staticmethod
    def _evaluate_osv(
        payload: Mapping[str, Any], fixture: Mapping[str, Any]
    ) -> list[str]:
        """Evaluate bounded exact-version advisories without provider/network state."""

        try:
            package = json.loads(str(fixture["content"]))
        except json.JSONDecodeError as exc:
            raise QualityEvaluationError("OSV fixture content must be package JSON.") from exc
        name = str(package.get("name", ""))
        ecosystem = str(package.get("ecosystem", ""))
        version = str(package.get("version", ""))
        for affected in payload.get("affected", []):
            target = affected.get("package", {})
            if target.get("name") == name and target.get("ecosystem") == ecosystem:
                if version in {str(item) for item in affected.get("versions", [])}:
                    identity = f"{payload.get('id')}:{ecosystem}:{name}:{version}"
                    return [hashlib.sha256(identity.encode()).hexdigest()]
        return []

    async def _run_process(self, *args: str, allow_nonzero: bool = False) -> str:
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise QualityEvaluationError("Required sandbox scanner is unavailable.") from exc
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout_seconds
            )
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise QualityEvaluationError("Candidate sandbox execution timed out.") from exc
        if process.returncode and not allow_nonzero:
            raise QualityEvaluationError(
                f"Candidate sandbox execution failed with exit code {process.returncode}: "
                f"{stderr.decode('utf-8', errors='replace')[:300]}"
            )
        return stdout.decode("utf-8", errors="replace")


def _language_suffix(language: str) -> str:
    return {
        "python": ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "java": ".java",
        "go": ".go",
        "ruby": ".rb",
        "php": ".php",
        "json": ".json",
        "text": ".txt",
    }.get(language.lower(), ".txt")


def _match_identity(rule_id: str, item: Mapping[str, Any]) -> str:
    start = item.get("start") or {}
    path = Path(str(item.get("path", ""))).name
    return hashlib.sha256(
        f"{rule_id}:{path}:{start.get('line')}:{start.get('col')}".encode()
    ).hexdigest()
