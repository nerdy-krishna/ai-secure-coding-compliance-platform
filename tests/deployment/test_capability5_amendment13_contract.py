"""Capability 5 Amendment 13 Kubernetes Pod/attach deployment contracts."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "sccap"
DIGEST = "c" * 64


def _enabled_arguments() -> list[str]:
    arguments = [
        "--set",
        "runnerV3.enabled=true",
        "--set",
        "pentestController.enabled=true",
        "--set",
        "pentestToolPack.enabled=true",
        "--set",
        "pentestToolPack.runtimeManager.secretEncryptionAtRestReady=true",
        "--set",
        "pentestToolPack.runtimeManager.apiServerCidrs[0]=10.96.0.1/32",
        "--set-string",
        "pentestToolPack.runtimeManager.relayPublicConfig.gatewayEndpoint=https://sccap-api.sccap.svc.cluster.local/api/v1/pentesting/internal/relay",
        "--set-string",
        (
            "pentestToolPack.runtimeManager.relayImage="
            f"registry.invalid/sccap/relay@sha256:{DIGEST}"
        ),
    ]
    for collection, key_id in (
        ("grantKeys", "grant-active"),
        ("permitKeys", "permit-active"),
    ):
        prefix = f"pentestToolPack.runtimeManager.relayPublicConfig.{collection}[0]"
        arguments.extend(
            [
                "--set-string",
                f"{prefix}.key_id={key_id}",
                "--set-string",
                f"{prefix}.status=active",
                "--set-string",
                f"{prefix}.algorithm=Ed25519",
                "--set-string",
                f"{prefix}.public_key={'A' * 43}",
                "--set-string",
                f"{prefix}.not_before=2026-01-01T00:00:00Z",
                "--set-string",
                f"{prefix}.not_after=2030-01-01T00:00:00Z",
                "--set",
                f"{prefix}.revoked_at=null",
                "--set",
                f"{prefix}.revocation_code=null",
            ]
        )
    for runtime in ("playwright", "zap", "nuclei", "nmap"):
        arguments.extend(
            [
                "--set-string",
                (
                    f"pentestToolPack.runtimes.{runtime}.image="
                    f"registry.invalid/sccap/{runtime}@sha256:{DIGEST}"
                ),
            ]
        )
    return arguments


def _render() -> list[dict]:
    helm = shutil.which("helm")
    if helm is None:
        raise unittest.SkipTest("helm is required for rendered-manifest checks")
    completed = subprocess.run(
        [helm, "template", "contract", str(CHART), *_enabled_arguments()],
        check=True,
        capture_output=True,
        text=True,
    )
    return [item for item in yaml.safe_load_all(completed.stdout) if item]


def _resources(policy: dict) -> set[str]:
    return {
        resource
        for rule in policy["spec"]["matchConstraints"]["resourceRules"]
        for resource in rule["resources"]
    }


def _validation_text(policy: dict) -> str:
    return " ".join(
        validation["expression"] for validation in policy["spec"]["validations"]
    )


class Capability5Amendment13HelmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifests = _render()
        cls.role = next(
            item
            for item in cls.manifests
            if item["kind"] == "Role"
            and item["metadata"]["name"].endswith("pentest-runtime-manager")
        )

    def _pod_policy(self) -> dict:
        policies = [
            item
            for item in self.manifests
            if item["kind"] == "ValidatingAdmissionPolicy"
            and "pods" in _resources(item)
        ]
        self.assertEqual(
            len(policies),
            1,
            "Amendment 13 requires one fail-closed runtime Pod policy",
        )
        return policies[0]

    def test_runtime_manager_rbac_is_the_exact_attach_capability(self) -> None:
        actual = {
            (
                tuple(rule.get("apiGroups", [])),
                tuple(rule.get("resources", [])),
            ): set(rule["verbs"])
            for rule in self.role["rules"]
        }
        expected = {
            (("",), ("pods",)): {"create", "get", "delete"},
            (("",), ("pods/attach",)): {"create", "get"},
            (("",), ("services",)): {"create", "get", "delete"},
            (
                ("networking.k8s.io",),
                ("networkpolicies",),
            ): {"create", "get", "patch", "delete"},
            (("",), ("secrets",)): {"create", "delete"},
        }
        self.assertEqual(actual, expected)

    def test_rbac_omits_broad_discovery_and_dangerous_subresources(self) -> None:
        verbs = {verb for rule in self.role["rules"] for verb in rule.get("verbs", [])}
        resources = {
            resource
            for rule in self.role["rules"]
            for resource in rule.get("resources", [])
        }
        self.assertTrue({"list", "watch", "update"}.isdisjoint(verbs))
        self.assertTrue(
            {
                "pods/exec",
                "pods/log",
                "pods/portforward",
                "jobs",
            }.isdisjoint(resources)
        )
        secret_rule = next(
            rule for rule in self.role["rules"] if "secrets" in rule["resources"]
        )
        self.assertEqual(set(secret_rule["verbs"]), {"create", "delete"})

    def test_adapter_admission_targets_pods_not_jobs(self) -> None:
        policies = [
            item
            for item in self.manifests
            if item["kind"] == "ValidatingAdmissionPolicy"
        ]
        runtime_policies = [item for item in policies if "pods" in _resources(item)]
        self.assertEqual(len(runtime_policies), 1)
        policy = runtime_policies[0]
        self.assertEqual(policy["spec"]["failurePolicy"], "Fail")
        operations = {
            operation
            for rule in policy["spec"]["matchConstraints"]["resourceRules"]
            for operation in rule["operations"]
        }
        self.assertEqual(operations, {"CREATE"})
        self.assertFalse(any("jobs" in _resources(item) for item in policies))

    def test_pod_admission_binds_name_identity_image_and_command(self) -> None:
        policy = self._pod_policy()
        text = _validation_text(policy)
        for fragment in (
            "request.namespace",
            "object.metadata.name",
            "pt5-",
            "-adapter",
            "-relay",
            "pentest.sccap/tenant-id",
            "pentest.sccap/execution-id",
            "pentest.sccap/runtime-session-id",
            "pentest.sccap/lease-generation",
            "pentest.sccap/cancellation-generation",
            "pentest.sccap/runtime",
            "object.spec.containers.size() == 1",
            "@sha256:",
            "/opt/sccap-tool-runtimes/playwright-observe",
            "/opt/sccap-tool-runtimes/zap-passive",
            "/opt/sccap-tool-runtimes/nuclei-observe",
            "/opt/sccap-tool-runtimes/nmap-connect",
            "app.infrastructure.pentesting.tool_gateway.main",
        ):
            self.assertIn(fragment, text)

    def test_pod_admission_enforces_isolation_and_approved_volumes(self) -> None:
        policy = self._pod_policy()
        text = _validation_text(policy)
        for fragment in (
            "automountServiceAccountToken == false",
            "hostNetwork != true",
            "hostPID != true",
            "hostIPC != true",
            "runAsNonRoot == true",
            "allowPrivilegeEscalation == false",
            "readOnlyRootFilesystem == true",
            "capabilities.drop",
            "seccompProfile",
            "profiles/sccap-playwright-v1.62.0.json",
            "emptyDir",
            "secret",
            "/run/sccap-relay",
            "readOnly == true",
            "256",
        ):
            self.assertIn(fragment, text)
        self.assertNotIn("serviceAccountToken", text)
        self.assertNotIn("hostPath", text)

    def test_relay_pod_secret_and_network_policies_share_exact_identity(
        self,
    ) -> None:
        pod_policy = self._pod_policy()
        secret_policy = next(
            item
            for item in self.manifests
            if item["kind"] == "ValidatingAdmissionPolicy"
            and "secrets" in _resources(item)
        )
        secret_text = _validation_text(secret_policy)
        self.assertIn("ownerReferences[0].kind == 'Pod'", secret_text)
        self.assertIn("relay-session-grant.json", secret_text)
        self.assertIn("relay-private-key", secret_text)

        pod_text = _validation_text(pod_policy)
        self.assertIn("relay-authority", pod_text)
        self.assertIn("pentest.sccap/runtime'] == 'relay'", pod_text)
        self.assertIn("pentest.sccap/runtime'] == 'adapter'", pod_text)

        template_map = next(
            item
            for item in self.manifests
            if item["kind"] == "ConfigMap"
            and item["metadata"]["name"].endswith("pentest-tool-runtime-templates")
        )
        templates = json.loads(template_map["data"]["templates.json"])
        identity = templates["identity"]
        self.assertEqual(
            identity,
            {
                "tenantLabel": "pentest.sccap/tenant-id",
                "executionLabel": "pentest.sccap/execution-id",
                "runtimeSessionLabel": "pentest.sccap/runtime-session-id",
                "leaseGenerationLabel": "pentest.sccap/lease-generation",
                "cancellationGenerationLabel": (
                    "pentest.sccap/cancellation-generation"
                ),
            },
        )
        self.assertEqual(
            templates["adapterNetworkPolicy"]["selectorIdentity"], identity
        )
        self.assertEqual(templates["relayNetworkPolicy"]["selectorIdentity"], identity)


if __name__ == "__main__":
    unittest.main()
