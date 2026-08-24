from __future__ import annotations

import importlib.util
import inspect
import json
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sbom = _load("generate_release_sbom", "scripts/generate_release_sbom.py")
provenance = _load("generate_slsa_provenance", "scripts/generate_slsa_provenance.py")


class SupplyChainScriptTests(unittest.TestCase):
    digest = "sha256:" + "a" * 64
    revision = "b" * 40

    @staticmethod
    def _evidence(target: str) -> list[dict[str, str]]:
        return [
            {
                "name": name,
                "path": f"/usr/local/bin/{name}",
                "sha256": str(index) * 64,
                "version_output": f"{name} version {version}",
            }
            for index, (name, version) in enumerate(
                sbom.EXPECTED_SCANNERS[target].items(), start=1
            )
        ]

    def test_image_sboms_retain_syft_inventory_and_differ_by_target(self) -> None:
        raw = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"tools": {"components": [{"name": "syft"}]}},
            "components": [
                {"type": "operating-system", "name": "debian", "version": "12"},
                {"type": "library", "name": "fastapi", "version": "1"},
                {
                    "type": "library",
                    "name": "semgrep",
                    "version": "1.95.0",
                    "purl": "pkg:pypi/semgrep@1.95.0",
                    "bom-ref": "pkg:pypi/semgrep@1.95.0",
                },
            ],
            "dependencies": [
                {"ref": "pkg:pypi/semgrep@1.95.0", "dependsOn": []}
            ],
        }
        api = sbom.build(
            raw,
            image="ghcr.io/acme/sccap-api",
            digest=self.digest,
            target="api",
            revision=self.revision,
            source_date_epoch=1,
            scanner_evidence=self._evidence("api"),
        )
        worker = sbom.build(
            raw,
            image="ghcr.io/acme/sccap-worker",
            digest=self.digest,
            target="worker",
            revision=self.revision,
            source_date_epoch=1,
            scanner_evidence=self._evidence("worker"),
        )
        self.assertIn("debian", {item["name"] for item in api["components"]})
        self.assertNotIn(
            "osv-scanner-entrypoint", {item["name"] for item in api["components"]}
        )
        self.assertIn(
            "osv-scanner-entrypoint", {item["name"] for item in worker["components"]}
        )
        self.assertEqual(api["specVersion"], "1.5")
        self.assertEqual(api["dependencies"], raw["dependencies"])
        semgrep_entrypoint = next(
            item for item in api["components"] if item["name"] == "semgrep-entrypoint"
        )
        self.assertIn(
            {"name": "sccap:syft:package-bom-ref", "value": "pkg:pypi/semgrep@1.95.0"},
            semgrep_entrypoint["properties"],
        )
        self.assertNotEqual(api["serialNumber"], worker["serialNumber"])

    def test_scanner_version_mismatch_is_rejected(self) -> None:
        evidence = self._evidence("worker")
        evidence[-1]["version_output"] = "osv-scanner 99.0.0"
        with self.assertRaisesRegex(ValueError, "pinned version"):
            sbom.build(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [
                        {"name": "debian"},
                        {
                            "name": "semgrep",
                            "version": "1.95.0",
                            "purl": "pkg:pypi/semgrep@1.95.0",
                        },
                    ],
                },
                image="ghcr.io/acme/sccap-worker",
                digest=self.digest,
                target="worker",
                revision=self.revision,
                source_date_epoch=1,
                scanner_evidence=evidence,
            )

    def test_semgrep_entrypoint_requires_syft_package_binding(self) -> None:
        with self.assertRaisesRegex(ValueError, "Semgrep package"):
            sbom.build(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [{"name": "debian", "version": "12"}],
                },
                image="ghcr.io/acme/sccap-api",
                digest=self.digest,
                target="api",
                revision=self.revision,
                source_date_epoch=1,
                scanner_evidence=self._evidence("api"),
            )

    def test_image_inspection_disables_network_and_pull(self) -> None:
        completed = mock.Mock(stdout="[]", stderr="")
        with mock.patch.object(sbom.subprocess, "run", return_value=completed) as run:
            sbom.inspect_image("image@" + self.digest, "api")
        command = run.call_args.args[0]
        self.assertIn("--network=none", command)
        self.assertIn("--pull=never", command)
        self.assertIn("--read-only", command)
        version_args = json.loads(command[-1])
        self.assertEqual(version_args["gitleaks"], ["version"])
        self.assertEqual(version_args["semgrep"], ["--version"])
        self.assertIn("RLIMIT_FSIZE", sbom._INSPECTION_SCRIPT)
        self.assertNotIn("capture_output=True", sbom._INSPECTION_SCRIPT)

    def test_workflow_pulls_exact_digest_before_pull_never_inspection(self) -> None:
        workflow_path = ROOT / ".github/workflows/supply-chain-release.yml"
        if workflow_path.exists():
            workflow = workflow_path.read_text("utf-8")
            pull = 'docker pull "$IMAGE@$IMAGE_DIGEST"'
            generator = "python scripts/generate_release_sbom.py"
            self.assertIn(pull, workflow)
            self.assertLess(workflow.index(pull), workflow.index(generator))
        self.assertIn("--pull=never", inspect.getsource(sbom.inspect_image))

    def test_provenance_names_actual_workflow_and_no_false_timestamps(self) -> None:
        workflow_ref = (
            "acme/sccap/.github/workflows/supply-chain-release.yml@refs/tags/v1"
        )
        predicate = provenance.build_predicate(
            image="ghcr.io/acme/sccap-api",
            digest=self.digest,
            revision=self.revision,
            repository="acme/sccap",
            workflow_ref=workflow_ref,
            target="api",
            invocation_id="https://github.com/acme/sccap/actions/runs/1/attempts/1",
        )
        self.assertEqual(
            predicate["buildDefinition"]["buildType"],
            "https://github.com/" + workflow_ref,
        )
        self.assertNotIn("slsa-github-generator", str(predicate))
        self.assertNotIn("_type", predicate)
        self.assertNotIn("subject", predicate)
        self.assertNotIn("predicate", predicate)
        self.assertEqual(
            predicate["buildDefinition"]["externalParameters"]["imageDigest"],
            self.digest,
        )
        self.assertNotIn("startedOn", predicate["runDetails"]["metadata"])
        self.assertNotIn("finishedOn", predicate["runDetails"]["metadata"])
