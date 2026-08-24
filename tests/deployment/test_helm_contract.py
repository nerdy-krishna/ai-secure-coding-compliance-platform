"""Helm rendering and least-privilege deployment regressions."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "sccap"


def _render(*arguments: str) -> list[dict]:
    helm = shutil.which("helm")
    if helm is None:
        raise unittest.SkipTest("helm is required for rendered-manifest checks")
    completed = subprocess.run(
        [helm, "template", "contract", str(CHART), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return [item for item in yaml.safe_load_all(completed.stdout) if item]


class HelmChartContractTests(unittest.TestCase):
    def test_chart_targets_kubernetes_130_and_immutable_image_tags(self) -> None:
        chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
        schema = (CHART / "values.schema.json").read_text()
        self.assertEqual(chart["kubeVersion"], ">=1.30.0-0")
        self.assertIn('"not": {"const": "latest"}', schema)

    def test_default_render_isolates_pool_secrets_and_scaling(self) -> None:
        manifests = _render()
        deployments = {
            item["metadata"]["name"]: item
            for item in manifests
            if item["kind"] == "Deployment"
        }
        expected_secrets = {
            "contract-sccap-api": "sccap-api-runtime",
            "contract-sccap-worker-scanner": "sccap-scanner-runtime",
            "contract-sccap-worker-llm": "sccap-llm-runtime",
            "contract-sccap-worker-report": "sccap-report-runtime",
        }
        for name, expected_secret in expected_secrets.items():
            container = deployments[name]["spec"]["template"]["spec"]["containers"][0]
            self.assertEqual(
                container["envFrom"][0]["secretRef"]["name"], expected_secret
            )
        self.assertEqual(
            deployments["contract-sccap-api"]["spec"]["template"]["spec"]
            ["containers"][0]["image"],
            "ghcr.io/nerdy-krishna/sccap-api:1.0.0",
        )
        for name in (
            "contract-sccap-worker-scanner",
            "contract-sccap-worker-llm",
            "contract-sccap-worker-report",
        ):
            self.assertEqual(
                deployments[name]["spec"]["template"]["spec"]["containers"][0]
                ["image"],
                "ghcr.io/nerdy-krishna/sccap-worker:1.0.0",
            )

        migration = next(item for item in manifests if item["kind"] == "Job")
        migration_env_from = migration["spec"]["template"]["spec"]["containers"][
            0
        ]["envFrom"]
        self.assertEqual(
            migration_env_from,
            [{"secretRef": {"name": "sccap-migration-runtime"}}],
        )

        scaled = {
            item["metadata"]["name"]: item
            for item in manifests
            if item["kind"] == "ScaledObject"
        }
        self.assertEqual(
            scaled["contract-sccap-worker-scanner"]["spec"]["maxReplicaCount"], 20
        )
        self.assertEqual(
            scaled["contract-sccap-worker-llm"]["spec"]["maxReplicaCount"], 50
        )
        self.assertEqual(
            scaled["contract-sccap-worker-report"]["spec"]["maxReplicaCount"], 10
        )
        for item in scaled.values():
            self.assertEqual(len(item["spec"]["triggers"]), 2)
            self.assertEqual(
                item["spec"]["advanced"]["horizontalPodAutoscalerConfig"]
                ["behavior"]["scaleDown"]["stabilizationWindowSeconds"],
                60,
            )

    def test_network_policies_are_component_scoped(self) -> None:
        manifests = _render()
        policies = [item for item in manifests if item["kind"] == "NetworkPolicy"]
        self.assertGreaterEqual(len(policies), 6)
        for policy in policies:
            selector = policy["spec"]["podSelector"]["matchLabels"]
            self.assertIn("app.kubernetes.io/component", selector)
            for rule in policy["spec"].get("egress", []):
                for destination in rule.get("to", []):
                    self.assertNotEqual(destination.get("namespaceSelector"), {})
                if any("podSelector" in item for item in rule.get("to", [])):
                    self.assertTrue(rule.get("ports"), "same-namespace egress needs ports")
        worker_policies = [
            item
            for item in policies
            if item["spec"]["podSelector"]["matchLabels"]
            ["app.kubernetes.io/component"].startswith("worker-")
        ]
        self.assertTrue(worker_policies)
        self.assertTrue(all(item["spec"]["ingress"] == [] for item in worker_policies))

    def test_unified_render_preserves_prefetch_five_bridge(self) -> None:
        manifests = _render(
            "--set", "workerPools.splitEnabled=false",
            "--set", "workerPools.unified.enabled=true",
        )
        deployment = next(
            item
            for item in manifests
            if item["kind"] == "Deployment"
            and item["metadata"]["name"] == "contract-sccap-worker-unified"
        )
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        env = {item["name"]: item["value"] for item in container["env"]}
        self.assertEqual(env["WORKER_POOL"], "unified")
        self.assertEqual(env["WORKER_PREFETCH_COUNT"], "5")
        self.assertEqual(
            container["envFrom"][0]["secretRef"]["name"],
            "sccap-unified-runtime",
        )


if __name__ == "__main__":
    unittest.main()
