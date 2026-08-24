"""Fresh-install and upgrade contracts for Compose secret bootstrap."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "scripts" / "bootstrap_env_secrets.py"
SECRET_KEYS = {
    "SECRET_KEY",
    "ENCRYPTION_KEY",
    "POSTGRES_PASSWORD",
    "RABBITMQ_DEFAULT_PASS",
    "RABBITMQ_ERLANG_COOKIE",
    "QDRANT_API_KEY",
    "GRAFANA_ADMIN_PASSWORD",
    "LANGFUSE_POSTGRES_PASSWORD",
    "CLICKHOUSE_PASSWORD",
    "REDIS_PASSWORD",
    "MINIO_ROOT_PASSWORD",
    "LANGFUSE_ENCRYPTION_KEY",
    "LANGFUSE_SALT",
    "NEXTAUTH_SECRET",
    "LANGFUSE_INIT_USER_PASSWORD",
}


def _run_bootstrap(env_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BOOTSTRAP), "--env-file", str(env_file)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _values(env_file: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


class BootstrapEnvSecretsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.env_file = Path(self.temporary_directory.name) / ".env"

    def test_upgrade_adds_missing_cookie_without_disclosing_value(self) -> None:
        self.env_file.write_text(
            "RABBITMQ_DEFAULT_PASS=keep-existing-password\n"
            "SECRET_KEY=keep-existing-signing-key\n",
            encoding="utf-8",
        )

        completed = _run_bootstrap(self.env_file)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        values = _values(self.env_file)
        cookie = values["RABBITMQ_ERLANG_COOKIE"]
        self.assertTrue(cookie and not cookie.startswith("REPLACE_ME"))
        self.assertEqual(values["RABBITMQ_DEFAULT_PASS"], "keep-existing-password")
        self.assertEqual(values["SECRET_KEY"], "keep-existing-signing-key")
        self.assertNotIn(cookie, completed.stdout)
        self.assertNotIn(cookie, completed.stderr)

    def test_fresh_template_replaces_placeholders_and_preserves_valid_values(
        self,
    ) -> None:
        template = (ROOT / ".env.example").read_text(encoding="utf-8")
        template = template.replace(
            "RABBITMQ_DEFAULT_PASS=REPLACE_ME",
            "RABBITMQ_DEFAULT_PASS=valid-existing-password",
        )
        self.env_file.write_text(template, encoding="utf-8")

        completed = _run_bootstrap(self.env_file)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        values = _values(self.env_file)
        self.assertEqual(values["RABBITMQ_DEFAULT_PASS"], "valid-existing-password")
        self.assertNotEqual(values["RABBITMQ_ERLANG_COOKIE"], "REPLACE_ME")
        self.assertFalse(values["ENCRYPTION_KEY"].startswith("REPLACE_ME"))
        self.assertFalse(values["LANGFUSE_ENCRYPTION_KEY"].startswith("REPLACE_ME"))
        for key in SECRET_KEYS:
            value = values[key]
            self.assertNotIn(value, completed.stdout)
            self.assertNotIn(value, completed.stderr)

    def test_bootstrap_is_idempotent_and_restricts_env_permissions(self) -> None:
        self.env_file.write_text(
            "RABBITMQ_ERLANG_COOKIE=REPLACE_ME\n", encoding="utf-8"
        )
        os.chmod(self.env_file, 0o644)

        first = _run_bootstrap(self.env_file)
        first_content = self.env_file.read_text(encoding="utf-8")
        second = _run_bootstrap(self.env_file)

        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(self.env_file.read_text(encoding="utf-8"), first_content)
        self.assertEqual(stat.S_IMODE(self.env_file.stat().st_mode), 0o600)

    def test_windows_upgrade_normalizes_legacy_utf16_env(self) -> None:
        self.env_file.write_text(
            'RABBITMQ_ERLANG_COOKIE="REPLACE_ME"\r\n'
            "SECRET_KEY=keep-existing-signing-key\r\n",
            encoding="utf-16",
        )

        completed = _run_bootstrap(self.env_file)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        raw = self.env_file.read_bytes()
        self.assertFalse(raw.startswith((b"\xff\xfe", b"\xfe\xff")))
        values = _values(self.env_file)
        self.assertFalse(values["RABBITMQ_ERLANG_COOKIE"].startswith("REPLACE_ME"))
        self.assertEqual(values["SECRET_KEY"], "keep-existing-signing-key")

    def test_setup_frontends_use_shared_bootstrap(self) -> None:
        unix_setup = (ROOT / "setup.sh").read_text(encoding="utf-8")
        windows_setup = (ROOT / "setup.bat").read_text(encoding="utf-8")

        expected = "scripts/bootstrap_env_secrets.py --env-file .env"
        self.assertIn(f"python3 {expected}", unix_setup)
        self.assertIn(f"python {expected}", windows_setup)
