from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.infrastructure.scanners.osv_offline_replay import (
    OfflineSnapshotError,
    _run_replay_subprocess,
    load_offline_snapshot,
    run_offline_osv_replay,
)


def _snapshot(root: Path, content: bytes = b"immutable-osv-zip") -> Path:
    archive = root / "osv-scanner" / "PyPI" / "all.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(content)
    manifest = root / "snapshot.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "snapshot_id": "osv-2026-08-23T000000Z",
                "created_at": "2026-08-23T00:00:00Z",
                "files": [
                    {
                        "path": "osv-scanner/PyPI/all.zip",
                        "size_bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    archive.chmod(0o444)
    manifest.chmod(0o444)
    archive.parent.chmod(0o555)
    archive.parent.parent.chmod(0o555)
    root.chmod(0o555)
    return manifest


class OfflineOSVSnapshotTests(unittest.TestCase):
    def test_manifest_binds_read_only_database_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "snapshot"
            root.mkdir()
            _snapshot(root)
            snapshot = load_offline_snapshot(root)

        self.assertEqual(snapshot.snapshot_id, "osv-2026-08-23T000000Z")
        self.assertEqual(snapshot.file_count, 1)
        self.assertEqual(len(snapshot.database_sha256), 64)
        self.assertTrue(snapshot.provenance()["immutable"])

    def test_content_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "snapshot"
            root.mkdir()
            _snapshot(root)
            archive = root / "osv-scanner" / "PyPI" / "all.zip"
            root.chmod(0o755)
            archive.parent.parent.chmod(0o755)
            archive.parent.chmod(0o755)
            archive.chmod(0o644)
            archive.write_bytes(b"changed")
            archive.chmod(0o444)
            archive.parent.chmod(0o555)
            archive.parent.parent.chmod(0o555)
            root.chmod(0o555)
            with self.assertRaisesRegex(
                OfflineSnapshotError, "snapshot_content_mismatch"
            ):
                load_offline_snapshot(root)

    def test_symlinked_database_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "snapshot"
            root.mkdir()
            _snapshot(root)
            archive = root / "osv-scanner" / "PyPI" / "all.zip"
            root.chmod(0o755)
            archive.parent.parent.chmod(0o755)
            archive.parent.chmod(0o755)
            archive.unlink()
            target = Path(tmp) / "target.zip"
            target.write_bytes(b"immutable-osv-zip")
            target.chmod(0o444)
            archive.symlink_to(target)
            archive.parent.chmod(0o555)
            archive.parent.parent.chmod(0o555)
            root.chmod(0o555)
            with self.assertRaisesRegex(
                OfflineSnapshotError, "snapshot_symlink_rejected"
            ):
                load_offline_snapshot(root)

    def test_subprocess_has_offline_flags_and_stripped_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            root = tmp_root / "snapshot"
            root.mkdir()
            _snapshot(root)
            snapshot = load_offline_snapshot(root)
            staged = tmp_root / "target"
            staged.mkdir()
            output = tmp_root / "result.json"
            completed = subprocess.CompletedProcess([], 0, "", "")
            with patch.dict(os.environ, {"HTTPS_PROXY": "secret-proxy"}), patch(
                "app.infrastructure.scanners.osv_offline_replay.run_owned_subprocess",
                return_value=completed,
            ) as run:
                _run_replay_subprocess("/scanner", staged, output, snapshot)

        argv = run.call_args.args[0]
        self.assertIn("--offline", argv)
        self.assertIn("--offline-vulnerabilities", argv)
        self.assertIn("--no-resolve", argv)
        self.assertNotIn("--download-offline-databases", argv)
        self.assertNotIn("HTTPS_PROXY", run.call_args.kwargs["env"])


class OfflineOSVReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_valid_native_report_maps_staged_path_and_records_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            root = tmp_root / "snapshot"
            root.mkdir()
            _snapshot(root)
            staged = tmp_root / "target"
            staged.mkdir()
            lockfile = staged / "requirements.txt"
            lockfile.write_text("demo==1.0\n", encoding="utf-8")
            binary = tmp_root / "bin" / "osv-scanner"
            binary.parent.mkdir()
            binary.write_bytes(b"binary")
            binary.chmod(0o555)
            raw = {
                "results": [
                    {
                        "source": {"path": str(lockfile)},
                        "packages": [
                            {
                                "package": {
                                    "name": "demo",
                                    "ecosystem": "PyPI",
                                    "version": "1.0",
                                },
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-test",
                                        "aliases": ["CVE-2026-0001"],
                                        "summary": "demo vulnerability",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }

            def write_report(_binary, _staged, output, _snapshot):
                output.write_text(json.dumps(raw), encoding="utf-8")
                return 1, ""

            with patch.dict(
                os.environ, {"OSV_OFFLINE_SNAPSHOT_DIR": str(root)}, clear=False
            ), patch(
                "app.infrastructure.scanners.osv_offline_replay._osv_binary",
                return_value=str(binary),
            ), patch(
                "app.infrastructure.scanners.osv_offline_replay._run_replay_subprocess",
                side_effect=write_report,
            ):
                result = await run_offline_osv_replay(
                    staged, {lockfile.resolve(): "requirements.txt"}
                )

        self.assertEqual(result.status, "passed")
        self.assertEqual(result.findings[0].file_path, "requirements.txt")
        self.assertEqual(result.findings[0].cve_id, "CVE-2026-0001")
        self.assertEqual(
            result.snapshot_provenance["snapshot_id"],
            "osv-2026-08-23T000000Z",
        )

    async def test_missing_snapshot_is_explicit_tool_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OSV_OFFLINE_SNAPSHOT_DIR", None)
            result = await run_offline_osv_replay(Path("/tmp"), {})
        self.assertEqual(result.status, "tool_missing")
        self.assertIn("snapshot_unconfigured", result.detail)


if __name__ == "__main__":
    unittest.main()
