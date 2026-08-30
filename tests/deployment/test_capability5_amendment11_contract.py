"""Capability 5 Amendment 11 deployment boundary contracts."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "sccap"
DIGEST = "b" * 64


def _enabled_arguments(*, secret_ready: bool = True) -> list[str]:
    arguments = [
        "--set",
        "runnerV3.enabled=true",
        "--set",
        "pentestController.enabled=true",
        "--set",
        "pentestToolPack.enabled=true",
        "--set",
        "pentestToolPack.runtimeManager.apiServerCidrs[0]=10.96.0.1/32",
    ]
    if secret_ready:
        arguments.extend(
            [
                "--set",
                "pentestToolPack.runtimeManager.secretEncryptionAtRestReady=true",
                "--set-string",
                "pentestToolPack.runtimeManager.relayPublicConfig.gatewayEndpoint=https://sccap-api.sccap.svc.cluster.local/api/v1/pentesting/internal/relay",
                "--set-string",
                (
                    "pentestToolPack.runtimeManager.relayImage="
                    f"registry.invalid/sccap/relay@sha256:{DIGEST}"
                ),
            ]
        )
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


def _validation_text(policy: dict) -> str:
    return " ".join(
        validation["expression"] for validation in policy["spec"]["validations"]
    )


def _resources(policy: dict) -> set[str]:
    return {
        resource
        for rule in policy["spec"]["matchConstraints"]["resourceRules"]
        for resource in rule["resources"]
    }


class Capability5Amendment11HelmTests(unittest.TestCase):
    def test_no_shared_relay_deployment_service_or_network_policy(self) -> None:
        manifests = _render(*_enabled_arguments())
        shared_kinds = {
            (item["kind"], item["metadata"]["name"])
            for item in manifests
            if "pentest-scope-relay" in item["metadata"]["name"]
        }
        self.assertEqual(
            shared_kinds,
            set(),
            "Amendment 11 permits only per-Execution relay workloads",
        )

    def test_runtime_manager_secret_rbac_is_create_delete_only(self) -> None:
        manifests = _render(*_enabled_arguments())
        role = next(
            item
            for item in manifests
            if item["kind"] == "Role"
            and item["metadata"]["name"].endswith("pentest-runtime-manager")
        )
        secret_rules = [
            rule for rule in role["rules"] if "secrets" in rule.get("resources", [])
        ]
        self.assertEqual(len(secret_rules), 1)
        self.assertEqual(set(secret_rules[0]["verbs"]), {"create", "delete"})
        self.assertTrue(
            {"get", "list", "watch", "update", "patch"}.isdisjoint(
                secret_rules[0]["verbs"]
            )
        )

    def test_secret_admission_is_fail_closed_and_exact_shape(self) -> None:
        manifests = _render(*_enabled_arguments())
        policies = [
            item
            for item in manifests
            if item["kind"] == "ValidatingAdmissionPolicy"
            and "secrets" in _resources(item)
        ]
        self.assertEqual(len(policies), 1)
        policy = policies[0]
        self.assertEqual(policy["spec"]["failurePolicy"], "Fail")
        text = _validation_text(policy)
        expected_fragments = (
            "request.namespace",
            "object.metadata.name",
            "object.metadata.labels",
            "pentest.sccap/execution-id",
            "pentest.sccap/runtime-session-id",
            "ownerReferences",
            "object.immutable == true",
            "relay-session-grant.json",
            "relay-private-key",
            "object.data",
            "size()",
        )
        for fragment in expected_fragments:
            self.assertIn(fragment, text)
        self.assertTrue(
            "object.data.size() == 2" in text
            or "object.data.keys().size() == 2" in text
        )

    def test_relay_workload_admission_binds_secret_mount_and_identity(self) -> None:
        manifests = _render(*_enabled_arguments())
        pod_policies = [
            item
            for item in manifests
            if item["kind"] == "ValidatingAdmissionPolicy"
            and "pods" in _resources(item)
        ]
        self.assertEqual(len(pod_policies), 1)
        text = _validation_text(pod_policies[0])
        for fragment in (
            "pentest.sccap/execution-id",
            "pentest.sccap/runtime-session-id",
            "pentest.sccap/runtime",
            "relay",
            "secret",
            "readOnly",
        ):
            self.assertIn(fragment, text)
        self.assertTrue("0400" in text or "256" in text)

    def test_runtime_templates_are_per_execution_and_have_relay_entrypoint(
        self,
    ) -> None:
        manifests = _render(*_enabled_arguments())
        template_map = next(
            item
            for item in manifests
            if item["kind"] == "ConfigMap"
            and item["metadata"]["name"].endswith("pentest-tool-runtime-templates")
        )
        self.assertTrue(template_map["immutable"])
        data_text = " ".join(template_map["data"].values())
        for fragment in (
            "execution-id",
            "runtime-session-id",
            "adapterNetworkPolicy",
            "relayNetworkPolicy",
            "app.infrastructure.pentesting.tool_gateway.main",
        ):
            self.assertIn(fragment, data_text)

    def test_production_secret_encryption_readiness_is_explicit_and_required(
        self,
    ) -> None:
        values = yaml.safe_load((CHART / "values.yaml").read_text())
        readiness = values["pentestToolPack"]["runtimeManager"]
        self.assertIn("secretEncryptionAtRestReady", readiness)
        self.assertIs(readiness["secretEncryptionAtRestReady"], False)

        schema = json.loads((CHART / "values.schema.json").read_text())
        manager = schema["properties"]["pentestToolPack"]["properties"][
            "runtimeManager"
        ]
        self.assertIn("secretEncryptionAtRestReady", manager["required"])
        self.assertEqual(
            manager["properties"]["secretEncryptionAtRestReady"]["type"],
            "boolean",
        )

        helm = shutil.which("helm")
        if helm is None:
            raise unittest.SkipTest("helm is required for rendered-manifest checks")
        completed = subprocess.run(
            [
                helm,
                "template",
                "contract",
                str(CHART),
                *_enabled_arguments(secret_ready=False),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Secret encryption at rest", completed.stderr)


if __name__ == "__main__":
    unittest.main()
