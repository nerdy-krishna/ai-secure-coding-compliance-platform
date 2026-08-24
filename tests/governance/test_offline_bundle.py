from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, utils

from app.infrastructure.governance import offline_bundle as offline_bundle_module
from app.infrastructure.governance.contracts import canonical_json
from app.infrastructure.governance.offline_bundle import (
    OfflineBundleError,
    activate_bundle,
    build_bundle,
    resolve_active_bundle,
    rollback_bundle,
    verify_bundle,
)
from app.infrastructure.scanners.osv_offline_replay import load_offline_snapshot
from app.infrastructure.signing.digest_signer import (
    DigestSignature,
    LocalTestDigestSigner,
)
from app.infrastructure.signing.public_key_verifier import (
    Ed25519FileDigestSigner,
    PinnedRsaPublicKeyDigestVerifier,
)


class OfflineBundleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        scanners = self.root / "scanners"
        rules = self.root / "rules"
        advisory = self.root / "advisory"
        scanners.mkdir()
        rules.mkdir()
        advisory.mkdir()
        scanner_versions = {
            "semgrep": ("python/bin/semgrep", "1.95.0"),
            "gitleaks": ("go/bin/gitleaks", "8.21.2"),
            "osv-scanner": ("osv/bin/osv-scanner", "2.3.5"),
        }
        for name, (relative, version) in scanner_versions.items():
            path = scanners / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f"#!/bin/sh\nprintf '%s\\n' '{name} version {version}'\n", "utf-8"
            )
            path.chmod(0o755)
        (rules / "semgrep.yml").write_text("rules: []\n", "utf-8")
        (rules / "gitleaks.toml").write_text("title = 'offline'\n", "utf-8")
        self._write_advisory(advisory, 1)
        self.components = {
            "scanners": scanners,
            "rules": rules,
            "advisory": advisory,
        }
        self.signer = LocalTestDigestSigner()
        self.state_signer = LocalTestDigestSigner(b"deployment-ledger-test-only")

    @staticmethod
    def _write_advisory(advisory: Path, version: int) -> None:
        database = advisory / "osv-scanner" / "PyPI" / "all.zip"
        database.parent.mkdir(parents=True, exist_ok=True)
        database.write_bytes(f"osv-database-v{version}".encode())
        (advisory / "snapshot.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "snapshot_id": f"test-v{version}",
                    "created_at": "2026-08-24T00:00:00Z",
                    "files": [
                        {
                            "path": "osv-scanner/PyPI/all.zip",
                            "size_bytes": database.stat().st_size,
                            "sha256": hashlib.sha256(database.read_bytes()).hexdigest(),
                        }
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            "utf-8",
        )

    def tearDown(self) -> None:
        for path in sorted(
            (item for item in self.root.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
        ):
            path.chmod(0o700)
        self.temporary.cleanup()

    async def _build(self, name: str, version: str, epoch: int):
        path = self.root / name
        verified = await build_bundle(
            output=path,
            version=version,
            components=self.components,
            signer=self.signer,
            source_date_epoch=epoch,
        )
        return path, verified

    @staticmethod
    def _scanner_smoke(binary: Path, arguments: tuple[str, ...]) -> str:
        completed = subprocess.run(
            [str(binary), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return completed.stdout + completed.stderr

    async def test_reproducible_bundle_verifies_concrete_runtime_contract(self) -> None:
        first, one = await self._build("first.tar", "2026.08.24", 1_787_500_000)
        os.utime(self.components["rules"] / "semgrep.yml", (1, 2))
        second, two = await self._build("second.tar", "2026.08.24", 1_787_500_000)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(one.bundle_sha256, two.bundle_sha256)
        self.assertEqual(
            set(one.manifest["runtime_contract"]["scanners"]),
            {"semgrep", "gitleaks", "osv-scanner"},
        )

    async def test_missing_scanner_or_rule_semantics_are_rejected(self) -> None:
        (self.components["scanners"] / "osv/bin/osv-scanner").unlink()
        with self.assertRaisesRegex(OfflineBundleError, "osv-scanner"):
            await self._build("missing.tar", "v1", 1)
        (self.components["scanners"] / "osv/bin/osv-scanner").write_text(
            "#!/bin/sh\necho 'osv-scanner 2.3.5'\n", "utf-8"
        )
        (self.components["scanners"] / "osv/bin/osv-scanner").chmod(0o755)
        (self.components["rules"] / "gitleaks.toml").unlink()
        with self.assertRaisesRegex(OfflineBundleError, "Gitleaks"):
            await self._build("missing-rule.tar", "v1", 1)

    async def test_archive_overhead_is_included_in_bundle_size_cap(self) -> None:
        with mock.patch.object(offline_bundle_module, "MAX_BUNDLE_BYTES", 2_000):
            with self.assertRaisesRegex(OfflineBundleError, "archive overhead"):
                await self._build("overhead.tar", "v1", 1)

    async def test_payload_tamper_is_rejected(self) -> None:
        bundle, _ = await self._build("bundle.tar", "v1", 1)
        body = bundle.read_bytes().replace(b"rules: []", b"rules: xx", 1)
        bundle.write_bytes(body)
        with self.assertRaises(OfflineBundleError):
            await verify_bundle(bundle=bundle, signer=self.signer)

    async def test_verification_streams_bundle_instead_of_reading_it_whole(
        self,
    ) -> None:
        bundle, _ = await self._build("streamed.tar", "v1", 1)
        original = Path.read_bytes

        def guarded(path: Path) -> bytes:
            if path == bundle:
                raise AssertionError("bundle.read_bytes() must not be used")
            return original(path)

        with mock.patch.object(Path, "read_bytes", guarded):
            await verify_bundle(bundle=bundle, signer=self.signer)

    async def test_invalid_manifest_signature_is_rejected_before_payload_hashing(
        self,
    ) -> None:
        bundle, _ = await self._build("bad-signature.tar", "v1", 1)

        class RejectingVerifier:
            async def verify_sha256(self, digest, signature):
                return False

        with mock.patch.object(
            offline_bundle_module,
            "_hash_stream",
            side_effect=AssertionError(
                "payload must not be hashed before signature verification"
            ),
        ):
            with self.assertRaisesRegex(OfflineBundleError, "signature is invalid"):
                await verify_bundle(bundle=bundle, signer=RejectingVerifier())

    async def test_activation_rollback_and_resolver_reverify_signed_state(self) -> None:
        install = self.root / "install"
        first, one = await self._build("v1.tar", "v1", 1)
        await activate_bundle(
            bundle=first,
            install_root=install,
            signer=self.signer,
            state_signer=self.state_signer,
            occurred_at="2026-08-24T01:00:00Z",
            scanner_smoke_runner=self._scanner_smoke,
        )
        self._write_advisory(self.components["advisory"], 2)
        second, two = await self._build("v2.tar", "v2", 2)
        await activate_bundle(
            bundle=second,
            install_root=install,
            signer=self.signer,
            state_signer=self.state_signer,
            occurred_at="2026-08-24T02:00:00Z",
            scanner_smoke_runner=self._scanner_smoke,
        )
        paths = await resolve_active_bundle(
            install_root=install,
            signer=self.signer,
            state_signer=self.state_signer,
        )
        self.assertEqual(paths.release_sha256, two.bundle_sha256)
        snapshot = load_offline_snapshot(paths.osv_advisory_root)
        self.assertEqual(snapshot.snapshot_id, "test-v2")
        installed_database = (
            paths.osv_advisory_root / "osv-scanner" / "PyPI" / "all.zip"
        )
        self.assertEqual(installed_database.stat().st_mode & 0o777, 0o444)
        self.assertEqual(paths.release_root.stat().st_mode & 0o777, 0o555)
        with self.assertRaises(PermissionError):
            installed_database.write_bytes(b"mutate")
        restored = await rollback_bundle(
            install_root=install,
            signer=self.signer,
            state_signer=self.state_signer,
            occurred_at="2026-08-24T03:00:00Z",
        )
        self.assertEqual(restored, one.bundle_sha256)
        state = json.loads((install / "deployment-state.json").read_text("utf-8"))
        self.assertEqual(
            [entry["action"] for entry in state["ledger"]["entries"]],
            ["activate", "activate", "rollback"],
        )
        self.assertIn("signature_b64", state["signature"])

    async def test_activation_smoke_checks_exact_nested_binaries_and_versions(
        self,
    ) -> None:
        install = self.root / "install"
        bundle, _ = await self._build("smoke.tar", "v1", 1)
        observed: list[tuple[str, tuple[str, ...]]] = []

        def wrong_gitleaks(binary: Path, arguments: tuple[str, ...]) -> str:
            observed.append((binary.relative_to(install).as_posix(), arguments))
            if binary.name == "gitleaks":
                return "gitleaks version 99.0.0"
            return self._scanner_smoke(binary, arguments)

        with self.assertRaisesRegex(OfflineBundleError, "pinned version 8.21.2"):
            await activate_bundle(
                bundle=bundle,
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
                scanner_smoke_runner=wrong_gitleaks,
            )
        self.assertIn(
            (
                next(path for path, _ in observed if path.endswith("go/bin/gitleaks")),
                ("version",),
            ),
            observed,
        )
        self.assertFalse((install / "deployment-state.json").exists())

    def test_production_smoke_runner_requires_verified_network_none_boundary(
        self,
    ) -> None:
        observed: list[str] = []

        def completed(command, **kwargs):
            observed.extend(command)
            kwargs["stdout"].write(b"semgrep 1.95.0\n")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temporary:
            interfaces = Path(temporary)
            (interfaces / "lo").mkdir()
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "SCCAP_OFFLINE_ACTIVATION_NETWORK_ISOLATION": "compose_network_none"
                    },
                    clear=False,
                ),
                mock.patch.object(
                    offline_bundle_module, "NETWORK_INTERFACE_ROOT", interfaces
                ),
                mock.patch.object(
                    offline_bundle_module.subprocess, "run", side_effect=completed
                ),
            ):
                output = offline_bundle_module._networkless_scanner_version(
                    Path("/verified/semgrep"), ("--version",)
                )
        self.assertEqual(observed, ["/verified/semgrep", "--version"])
        self.assertEqual(output.strip(), "semgrep 1.95.0")

    def test_production_smoke_runner_rejects_marker_without_network_none(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            interfaces = Path(temporary)
            (interfaces / "lo").mkdir()
            (interfaces / "eth0").mkdir()
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "SCCAP_OFFLINE_ACTIVATION_NETWORK_ISOLATION": "compose_network_none"
                    },
                    clear=False,
                ),
                mock.patch.object(
                    offline_bundle_module, "NETWORK_INTERFACE_ROOT", interfaces
                ),
            ):
                with self.assertRaisesRegex(OfflineBundleError, "network_mode none"):
                    offline_bundle_module._networkless_scanner_version(
                        Path("/verified/semgrep"), ("--version",)
                    )

    async def test_state_and_installed_payload_tamper_fail_closed(self) -> None:
        install = self.root / "install"
        bundle, verified = await self._build("v1.tar", "v1", 1)
        await activate_bundle(
            bundle=bundle,
            install_root=install,
            signer=self.signer,
            state_signer=self.state_signer,
            scanner_smoke_runner=self._scanner_smoke,
        )
        state_path = install / "deployment-state.json"
        state_path.write_bytes(
            state_path.read_bytes().replace(b'"active"', b'"activE"', 1)
        )
        with self.assertRaises(OfflineBundleError):
            await resolve_active_bundle(
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
            )
        # Restore a valid signed state idempotently, then corrupt active content.
        state_path.unlink()
        (install / "current").unlink()
        await activate_bundle(
            bundle=bundle,
            install_root=install,
            signer=self.signer,
            state_signer=self.state_signer,
            scanner_smoke_runner=self._scanner_smoke,
        )
        payload = (
            install
            / "releases"
            / verified.bundle_sha256
            / "advisory"
            / "osv-scanner"
            / "PyPI"
            / "all.zip"
        )
        payload.chmod(0o644)
        payload.write_text("tampered", "utf-8")
        with self.assertRaises(OfflineBundleError):
            await resolve_active_bundle(
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
            )

    async def test_repeated_rollback_preserves_forward_history(self) -> None:
        install = self.root / "install"
        releases = []
        for index in range(1, 4):
            self._write_advisory(self.components["advisory"], index)
            bundle, verified = await self._build(f"v{index}.tar", f"v{index}", index)
            releases.append(verified.bundle_sha256)
            await activate_bundle(
                bundle=bundle,
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
                occurred_at=f"2026-08-24T0{index}:00:00Z",
                scanner_smoke_runner=self._scanner_smoke,
            )
        self.assertEqual(
            await rollback_bundle(
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
                occurred_at="2026-08-24T04:00:00Z",
            ),
            releases[1],
        )
        self.assertEqual(
            await rollback_bundle(
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
                occurred_at="2026-08-24T05:00:00Z",
            ),
            releases[2],
        )

    async def test_resigned_inconsistent_history_and_manifest_binding_are_rejected(
        self,
    ) -> None:
        install = self.root / "install"
        bundle, _ = await self._build("ledger.tar", "v1", 1)
        await activate_bundle(
            bundle=bundle,
            install_root=install,
            signer=self.signer,
            state_signer=self.state_signer,
            scanner_smoke_runner=self._scanner_smoke,
        )
        state_path = install / "deployment-state.json"

        async def resign(envelope: dict) -> None:
            ledger_digest = hashlib.sha256(canonical_json(envelope["ledger"])).digest()
            signature = await self.state_signer.sign_sha256(ledger_digest)
            envelope["signature"] = {
                "ledger_sha256": ledger_digest.hex(),
                "signature_b64": signature.signature_b64,
                "algorithm": signature.algorithm,
                "key_id": signature.key_id,
            }
            state_path.write_bytes(canonical_json(envelope))

        original = json.loads(state_path.read_text("utf-8"))
        bad_history = json.loads(json.dumps(original))
        bad_history["ledger"]["history"] = [bad_history["ledger"]["active"]]
        await resign(bad_history)
        with self.assertRaisesRegex(OfflineBundleError, "ledger active release"):
            await resolve_active_bundle(
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
            )

        bad_manifest = json.loads(json.dumps(original))
        bad_manifest["ledger"]["entries"][-1]["release_manifest_sha256"] = "0" * 64
        await resign(bad_manifest)
        with self.assertRaisesRegex(OfflineBundleError, "signed deployment state"):
            await resolve_active_bundle(
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
            )

    async def test_pointer_tamper_is_rejected_by_runtime_resolver(self) -> None:
        install = self.root / "install"
        bundle, _ = await self._build("v1.tar", "v1", 1)
        await activate_bundle(
            bundle=bundle,
            install_root=install,
            signer=self.signer,
            state_signer=self.state_signer,
            scanner_smoke_runner=self._scanner_smoke,
        )
        (install / "current").unlink()
        (install / "current").symlink_to("releases/" + "0" * 64)
        with self.assertRaisesRegex(OfflineBundleError, "signed state"):
            await resolve_active_bundle(
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
            )

    async def test_release_root_symlink_is_rejected(self) -> None:
        bundle, _ = await self._build("symlink.tar", "v1", 1)
        install = self.root / "unsafe-install"
        outside = self.root / "outside-releases"
        install.mkdir()
        outside.mkdir()
        (install / "releases").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(OfflineBundleError, "releases root"):
            await activate_bundle(
                bundle=bundle,
                install_root=install,
                signer=self.signer,
                state_signer=self.state_signer,
                scanner_smoke_runner=self._scanner_smoke,
            )


class PinnedPublicVerifierTests(unittest.IsolatedAsyncioTestCase):
    def test_deployment_private_key_rejects_insecure_mode_and_symlink(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        fingerprint = hashlib.sha256(
            public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deployment.pem"
            path.write_bytes(
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                Ed25519FileDigestSigner(
                    private_key_path=path, public_key_sha256=fingerprint
                )
            path.chmod(0o600)
            Ed25519FileDigestSigner(
                private_key_path=path, public_key_sha256=fingerprint
            )
            link = Path(temporary) / "deployment-link.pem"
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "opened safely"):
                Ed25519FileDigestSigner(
                    private_key_path=link, public_key_sha256=fingerprint
                )

    async def test_rsa_public_key_verifies_without_kms_and_rejects_wrong_pin(
        self,
    ) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.pem"
            path.write_bytes(pem)
            key_id = "arn:aws:kms:us-east-1:123456789012:key/test"
            verifier = PinnedRsaPublicKeyDigestVerifier(
                public_key_path=path,
                public_key_sha256=hashlib.sha256(der).hexdigest(),
                expected_key_id=key_id,
            )
            digest = hashlib.sha256(b"manifest").digest()
            signature = private_key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256.digest_size,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
            valid = await verifier.verify_sha256(
                digest,
                DigestSignature(
                    signature_b64=base64.b64encode(signature).decode("ascii"),
                    algorithm="RSASSA_PSS_SHA_256",
                    key_id=key_id,
                ),
            )
            self.assertTrue(valid)
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                PinnedRsaPublicKeyDigestVerifier(
                    public_key_path=path,
                    public_key_sha256="0" * 64,
                    expected_key_id=key_id,
                )
