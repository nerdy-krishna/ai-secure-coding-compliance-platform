"""Real networkless compiler fixtures for non-Python remediation profiles."""

from __future__ import annotations

import asyncio
import unittest

from app.infrastructure.validation.sandbox_client import (
    run_sandbox_validation,
    select_validation_profiles,
)
from tests.integration.support import integration_test


VALID_FIXTURES = {
    "javascript_syntax": {"src/app.js": "const answer = 42;\n"},
    "typescript_check": {
        "src/app.ts": "const answer: number = 42;\n",
        "src/App.jsx": "export default <main>{answer}</main>;\n",
    },
    "go_compile": {
        "go.mod": "module example.invalid/fixture\n\ngo 1.19\n",
        "main.go": "package main\n\nfunc main() {}\n",
    },
    "java_compile": {
        "src/Main.java": (
            "public final class Main {\n"
            "    public static void main(String[] args) {}\n"
            "}\n"
        )
    },
}

INVALID_FIXTURES = {
    "javascript_syntax": {"src/app.js": "const = ;\n"},
    "typescript_check": {"src/app.ts": "const answer: string = 42;\n"},
    "go_compile": {
        "go.mod": "module example.invalid/fixture\n\ngo 1.19\n",
        "main.go": "package main\n\nfunc main( {}\n",
    },
    "java_compile": {
        "src/Main.java": 'public class Main { int value = "not-an-int"; }\n'
    },
}


async def run_fixture(profile: str, files: dict[str, str]):
    selected = select_validation_profiles(files)
    if selected != [profile]:
        raise AssertionError(f"profile selection mismatch: {selected}")
    checks = await run_sandbox_validation(files, selected, timeout_seconds=60)
    if len(checks) != 1:
        raise AssertionError(f"unexpected validation evidence: {checks}")
    return checks[0]


@integration_test
class NonPythonValidationProfileIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_valid_fixtures_compile_in_the_networkless_service(self) -> None:
        checks = await asyncio.gather(
            *(run_fixture(profile, files) for profile, files in VALID_FIXTURES.items())
        )
        self.assertEqual([check.status for check in checks], ["passed"] * 4)
        for check in checks:
            self.assertTrue(check.blocking)
            self.assertIn("Toolchain:", check.detail)

    async def test_invalid_fixtures_are_blocking_failures(self) -> None:
        checks = await asyncio.gather(
            *(
                run_fixture(profile, files)
                for profile, files in INVALID_FIXTURES.items()
            )
        )
        self.assertEqual([check.status for check in checks], ["failed"] * 4)
        for check in checks:
            self.assertTrue(check.blocking)
            self.assertNotEqual(check.return_code, 0)


if __name__ == "__main__":
    unittest.main()
