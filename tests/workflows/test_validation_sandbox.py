import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.infrastructure.validation.sandbox_client import (
    _run_job,
    select_validation_profiles,
)
from app.shared.lib.validation_sandbox_runner import process_job


def job(files, profiles, timeout=5):
    return {
        "schema_version": 1,
        "files": files,
        "profiles": profiles,
        "timeout_seconds": timeout,
    }


class ValidationSandboxRunnerTests(unittest.TestCase):
    def test_python_compile_passes_without_executing_module_code(self):
        result = process_job(
            job(
                {
                    "app.py": (
                        "from pathlib import Path\n"
                        "Path('should-not-exist').write_text('executed')\n"
                    )
                },
                ["python_compile"],
            )
        )
        self.assertEqual(result["checks"][0]["status"], "passed")
        self.assertNotIn("should-not-exist", result["checks"][0]["output"])

    def test_python_compile_failure_is_explicit(self):
        result = process_job(job({"app.py": "def broken(:\n"}, ["python_compile"]))
        self.assertEqual(result["checks"][0]["status"], "failed")
        self.assertNotEqual(result["checks"][0]["return_code"], 0)

    def test_non_allowlisted_profile_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            process_job(job({"app.py": "pass\n"}, ["sh -c env"]))

    def test_traversal_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid relative"):
            process_job(job({"../secret.py": "pass\n"}, ["python_compile"]))

    def test_timeout_kills_the_allowlisted_process_group(self):
        with patch.dict(
            "app.shared.lib.validation_sandbox_runner.PROFILE_COMMANDS",
            {"slow": ("python", "-I", "-c", "import time; time.sleep(5)")},
            clear=True,
        ):
            result = process_job(job({"app.py": "pass\n"}, ["slow"], timeout=1))
        self.assertEqual(result["checks"][0]["status"], "timeout")

    def test_child_adapter_exit_codes_preserve_failure_classification(self):
        for return_code, expected in (
            (126, "tool_missing"),
            (125, "infrastructure_error"),
        ):
            with (
                self.subTest(return_code=return_code),
                patch.dict(
                    "app.shared.lib.validation_sandbox_runner.PROFILE_COMMANDS",
                    {
                        "adapter": (
                            "python",
                            "-I",
                            "-c",
                            f"raise SystemExit({return_code})",
                        )
                    },
                    clear=True,
                ),
            ):
                result = process_job(job({"app.py": "pass\n"}, ["adapter"]))
            self.assertEqual(result["checks"][0]["status"], expected)


class ValidationSandboxClientTests(unittest.TestCase):
    def test_profiles_are_selected_from_repository_shape(self):
        self.assertEqual(
            select_validation_profiles(
                {"src/app.py": "pass\n", "tests/test_app.py": "pass\n"}
            ),
            ["python_compile", "python_pytest"],
        )
        self.assertEqual(
            select_validation_profiles({"src/app.py": "pass\n"}), ["python_compile"]
        )
        self.assertEqual(
            select_validation_profiles({"web/App.jsx": "export default null;\n"}),
            ["typescript_check"],
        )
        self.assertEqual(
            select_validation_profiles(
                {
                    "web/app.js": "export {};\n",
                    "web/app.tsx": "export {};\n",
                    "cmd/main.go": "package main\n",
                    "src/Main.java": "class Main {}\n",
                }
            ),
            [
                "javascript_syntax",
                "typescript_check",
                "go_compile",
                "java_compile",
            ],
        )

    def test_control_char_in_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid relative"):
            process_job(job({"bad\nname.py": "pass\n"}, ["python_compile"]))

    def test_absent_service_is_tool_missing_without_executing_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            checks = _run_job(
                {"app.py": "pass\n"},
                ["python_compile"],
                job_dir=Path(directory),
                timeout_seconds=1,
            )
        self.assertEqual(checks[0].status, "tool_missing")
        self.assertTrue(checks[0].blocking)


if __name__ == "__main__":
    unittest.main()
