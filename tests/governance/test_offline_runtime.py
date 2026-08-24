from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.infrastructure.governance.offline_bundle import OfflineRuntimePaths
from app.infrastructure.governance.offline_runtime import (
    configure_offline_runtime_from_environment,
)
from app.infrastructure.scanners import gitleaks_runner, provenance, semgrep_runner


class OfflineRuntimeBootstrapTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_runtime_remains_unchanged(self) -> None:
        environment: dict[str, str] = {}
        paths = await configure_offline_runtime_from_environment(environment)
        self.assertIsNone(paths)
        self.assertEqual(environment, {})

    async def test_verified_paths_are_consumed_by_scanner_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary)
            release = install / "releases" / ("a" * 64)
            (release / "scanners").mkdir(parents=True)
            (release / "rules").mkdir()
            (release / "advisory").mkdir()
            scanner_paths = {
                "semgrep": release / "scanners/python/bin/semgrep",
                "gitleaks": release / "scanners/go/bin/gitleaks",
                "osv-scanner": release / "scanners/osv/bin/osv-scanner",
            }
            for scanner, path in scanner_paths.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(scanner.encode())
            (release / "rules" / "gitleaks.toml").write_text("title='x'", "utf-8")
            paths = OfflineRuntimePaths(
                release_sha256="a" * 64,
                release_root=release,
                scanners=release / "scanners",
                rules=release / "rules",
                advisory=release / "advisory",
                semgrep_binary=scanner_paths["semgrep"],
                gitleaks_binary=scanner_paths["gitleaks"],
                osv_binary=scanner_paths["osv-scanner"],
                semgrep_rule_roots=(release / "rules",),
                gitleaks_config=release / "rules" / "gitleaks.toml",
                osv_advisory_root=release / "advisory",
            )
            environment = {
                "SCCAP_OFFLINE_INSTALL_ROOT": str(install),
                "OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY": "/trust/release.pem",
                "OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY_SHA256": "1" * 64,
                "OFFLINE_BUNDLE_RELEASE_KEY_ID": "arn:aws:kms:region:account:key/id",
                "OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY": "/trust/deployment.pem",
                "OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY_SHA256": "2" * 64,
            }
            with (
                mock.patch(
                    "app.infrastructure.governance.offline_runtime.PinnedRsaPublicKeyDigestVerifier"
                ),
                mock.patch(
                    "app.infrastructure.governance.offline_runtime.PinnedEd25519PublicKeyDigestVerifier"
                ),
                mock.patch(
                    "app.infrastructure.governance.offline_runtime.resolve_active_bundle",
                    new=mock.AsyncMock(return_value=paths),
                ) as resolve,
            ):
                result = await configure_offline_runtime_from_environment(environment)
            self.assertEqual(result, paths)
            resolve.assert_awaited_once()
            self.assertEqual(
                environment["SEMGREP_BINARY"], str(scanner_paths["semgrep"])
            )
            self.assertEqual(
                environment["SEMGREP_OFFLINE_RULE_ROOT"], str(release / "rules")
            )
            self.assertEqual(
                environment["GITLEAKS_CONFIG_PATH"], str(paths.gitleaks_config)
            )
            self.assertEqual(
                environment["OSV_OFFLINE_SNAPSHOT_DIR"], str(paths.advisory)
            )

    async def test_opt_in_with_incomplete_trust_configuration_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "RELEASE_PUBLIC_KEY"):
                await configure_offline_runtime_from_environment(
                    {"SCCAP_OFFLINE_INSTALL_ROOT": temporary}
                )


class OfflineScannerResolutionTests(unittest.IsolatedAsyncioTestCase):
    def test_bandit_provenance_is_not_relabelled_as_offline_bundle(self) -> None:
        specification = {
            "bandit": {
                "binary": lambda: "/bin/true",
                "version_args": ("--version",),
                "version": "1",
                "sha256": "0" * 64,
                "configuration_identifier": "bandit-default-plugins@1",
            }
        }
        provenance.collect_runtime_provenance.cache_clear()
        with (
            mock.patch.dict(
                os.environ,
                {"SCCAP_OFFLINE_VERIFIED_RELEASE_SHA256": "a" * 64},
                clear=False,
            ),
            mock.patch.object(provenance, "_SCANNER_SPECS", specification),
            mock.patch.object(
                provenance,
                "build_scanner_provenance",
                side_effect=lambda **kwargs: kwargs,
            ),
            mock.patch.object(provenance, "_detect_version", return_value="1"),
        ):
            record = provenance.collect_runtime_provenance()["bandit"]
        provenance.collect_runtime_provenance.cache_clear()
        self.assertEqual(record["configuration_identifier"], "bandit-default-plugins@1")

    def test_gitleaks_command_uses_verified_dynamic_config(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.dict(
                os.environ,
                {
                    "GITLEAKS_BINARY": "/verified/scanners/gitleaks",
                    "GITLEAKS_CONFIG_PATH": "/verified/rules/gitleaks.toml",
                },
                clear=False,
            ),
            mock.patch.object(
                gitleaks_runner, "run_owned_subprocess", return_value=completed
            ) as run,
        ):
            gitleaks_runner._invoke_gitleaks_sync(
                Path("/work/tree"), Path("/tmp/report.json")
            )
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/verified/scanners/gitleaks")
        self.assertEqual(
            command[command.index("--config") + 1], "/verified/rules/gitleaks.toml"
        )

    async def test_semgrep_uses_verified_offline_rule_root_when_database_is_empty(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess([], 0, '{"results":[],"errors":[]}', "")
        with (
            mock.patch.dict(
                os.environ,
                {
                    "SEMGREP_BINARY": "/verified/scanners/semgrep",
                    "SEMGREP_OFFLINE_RULE_ROOT": "/verified/rules",
                },
                clear=False,
            ),
            mock.patch.object(
                semgrep_runner.asyncio,
                "to_thread",
                new=mock.AsyncMock(return_value=completed),
            ) as to_thread,
        ):
            findings = await semgrep_runner.run_semgrep(Path("/work/tree"), {}, None)
        self.assertEqual(findings, [])
        self.assertEqual(to_thread.call_args.args[2], Path("/verified/rules"))

    async def test_semgrep_offline_rules_override_database_materialization(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess([], 0, '{"results":[],"errors":[]}', "")
        with (
            mock.patch.dict(
                os.environ,
                {"SEMGREP_OFFLINE_RULE_ROOT": "/verified/offline-rules"},
                clear=False,
            ),
            mock.patch.object(
                semgrep_runner.asyncio,
                "to_thread",
                new=mock.AsyncMock(return_value=completed),
            ) as to_thread,
        ):
            await semgrep_runner.run_semgrep(
                Path("/work/tree"), {}, Path("/database/materialized")
            )
        self.assertEqual(to_thread.call_args.args[2], Path("/verified/offline-rules"))
