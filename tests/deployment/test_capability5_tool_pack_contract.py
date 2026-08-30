"""Capability 5 default-off deployment and isolation contracts."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "sccap"
DIGEST = "a" * 64


def _enabled_arguments() -> list[str]:
    arguments = [
        "--set",
        "runnerV3.enabled=true",
        "--set",
        "pentestController.enabled=true",
        "--set",
        "pentestToolPack.enabled=true",
        "--set",
        "pentestToolPack.runtimeManager.apiServerCidrs[0]=10.96.0.1/32",
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


class Capability5ComposeContractTests(unittest.TestCase):
    def test_playwright_seccomp_profile_is_the_pinned_reviewed_file(self) -> None:
        profile = ROOT / "deploy" / "seccomp" / "sccap-playwright-v1.62.0.json"
        self.assertEqual(
            hashlib.sha256(profile.read_bytes()).hexdigest(),
            "cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849",
        )

    def test_tool_pack_is_default_off_and_result_key_is_file_mounted(self) -> None:
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
        worker = compose["services"]["pentest-tool-worker"]
        self.assertEqual(worker["profiles"], ["pentesting-v5"])
        self.assertEqual(worker["build"]["target"], "tool-supervisor")
        self.assertNotIn("pentest-scope-relay", compose["services"])
        environment = worker["environment"]
        self.assertEqual(
            environment["PENTEST_TOOL_RESULT_SIGNING_KEY_FILE"],
            "/run/secrets/pentest-tool-result-signing.key",
        )
        self.assertNotIn("PENTEST_TOOL_RESULT_SIGNING_SEED", environment)
        self.assertIn("PENTEST_TOOL_WORKER_RUNTIME_IMAGE_DIGESTS", environment)
        self.assertNotIn("DATABASE_URL", environment)
        self.assertNotIn("pentest-egress", worker["networks"])
        self.assertNotIn("PENTEST_SCOPE_RELAY_URL", environment)
        self.assertFalse(
            any("docker.sock" in str(volume) for volume in worker.get("volumes", []))
        )


class Capability5HelmContractTests(unittest.TestCase):
    def test_default_render_has_no_capability5_runtime(self) -> None:
        manifests = _render()
        names = {item["metadata"]["name"] for item in manifests}
        self.assertFalse(any("pentest-tool" in name for name in names))
        self.assertFalse(any("pentest-scope-relay" in name for name in names))

    def test_enabled_render_is_digest_pinned_and_least_privileged(self) -> None:
        manifests = _render(*_enabled_arguments())
        by_identity = {
            (item["kind"], item["metadata"]["name"]): item for item in manifests
        }
        worker = by_identity[("Deployment", "contract-sccap-pentest-tool-worker")]
        worker_container = worker["spec"]["template"]["spec"]["containers"][0]
        init_container = worker["spec"]["template"]["spec"]["initContainers"][0]
        self.assertFalse(
            worker["spec"]["template"]["spec"]["automountServiceAccountToken"]
        )
        self.assertTrue(worker_container["securityContext"]["readOnlyRootFilesystem"])
        env = {item["name"]: item for item in worker_container["env"]}
        self.assertIn("PENTEST_TOOL_RESULT_SIGNING_KEY_FILE", env)
        self.assertIn("PENTEST_TOOL_WORKER_RUNTIME_IMAGE_DIGESTS", env)
        self.assertNotIn("PENTEST_RESULT_SIGNING_SEED", env)
        self.assertNotIn("DATABASE_URL", env)
        self.assertEqual(init_container["command"][0], "/usr/bin/install")
        self.assertIn("0400", init_container["command"])
        self.assertEqual(
            init_container["securityContext"]["capabilities"]["add"], ["CHOWN"]
        )
        templates = by_identity[
            ("ConfigMap", "contract-sccap-pentest-tool-runtime-templates")
        ]
        self.assertTrue(templates["immutable"])
        for runtime in ("playwright", "zap", "nuclei", "nmap"):
            self.assertIn(
                f"{runtime}@sha256:{DIGEST}", templates["data"]["templates.json"]
            )
        self.assertIn(
            "app.infrastructure.pentesting.tool_gateway.main",
            templates["data"]["templates.json"],
        )

        role = by_identity[("Role", "contract-sccap-pentest-runtime-manager")]
        self.assertEqual(role["kind"], "Role")
        all_verbs = {verb for rule in role["rules"] for verb in rule["verbs"]}
        self.assertNotIn("update", all_verbs)
        secret_rule = next(
            rule for rule in role["rules"] if "secrets" in rule["resources"]
        )
        self.assertEqual(set(secret_rule["verbs"]), {"create", "delete"})
        admission = by_identity[
            ("ValidatingAdmissionPolicy", "contract-sccap-pentest-runtime-pods")
        ]
        validation_text = " ".join(
            item["expression"] for item in admission["spec"]["validations"]
        )
        self.assertIn("@sha256:", validation_text)
        self.assertIn("allowPrivilegeEscalation", validation_text)
        self.assertIn("readOnlyRootFilesystem", validation_text)

        scaled_objects = [
            item
            for item in manifests
            if item["kind"] == "ScaledObject"
            and item["metadata"]["name"] == "contract-sccap-pentest-tool-worker"
        ]
        self.assertEqual(len(scaled_objects), 1)
        self.assertEqual(
            scaled_objects[0]["spec"]["triggers"][0]["metadata"]["queueName"],
            "pentest_tool_queue_v1",
        )
        self.assertFalse(
            any(
                item["metadata"]["name"].endswith("pentest-scope-relay")
                for item in manifests
            )
        )

    def test_enabled_render_rejects_mutable_or_missing_runtime_images(self) -> None:
        helm = shutil.which("helm")
        if helm is None:
            raise unittest.SkipTest("helm is required for rendered-manifest checks")
        completed = subprocess.run(
            [
                helm,
                "template",
                "contract",
                str(CHART),
                "--set",
                "runnerV3.enabled=true",
                "--set",
                "pentestController.enabled=true",
                "--set",
                "pentestToolPack.enabled=true",
                "--set",
                "pentestToolPack.runtimeManager.apiServerCidrs[0]=10.96.0.1/32",
                "--set",
                "pentestToolPack.runtimeManager.secretEncryptionAtRestReady=true",
                "--set-string",
                (
                    "pentestToolPack.runtimeManager.relayImage="
                    f"registry.invalid/sccap/relay@sha256:{DIGEST}"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("repository@sha256", completed.stderr)


if __name__ == "__main__":
    unittest.main()
