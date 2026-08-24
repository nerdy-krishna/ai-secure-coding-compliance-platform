from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class CiHelperScriptTests(unittest.TestCase):
    def test_attacker_influenced_text_fields_are_literal_form_strings(self) -> None:
        script = Path(__file__).resolve().parents[2] / "scripts" / "sccap-ci-policy.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "curl-arguments.log"
            archive = root / "source.zip"
            archive.write_bytes(b"archive")
            curl = root / "curl"
            curl.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" >> \"$CURL_LOG\"\n"
                "case \"$*\" in\n"
                "  *'/ci/submissions'*) printf '%s' '{\"scan_id\":\"scan-1\"}' ;;\n"
                "  *'/policy'*) printf '%s' '{\"terminal\":true,\"outcome\":\"pass\"}' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            jq = root / "jq"
            jq.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *'.scan_id'*) printf '%s\\n' 'scan-1' ;;\n"
                "  *'.terminal'*) printf '%s\\n' 'true' ;;\n"
                "  *'.outcome'*) printf '%s\\n' 'pass' ;;\n"
                "  *'.report_url'*) printf '\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            curl.chmod(0o700)
            jq.chmod(0o700)
            malicious = "@/etc/passwd"
            environment = {
                **os.environ,
                "PATH": f"{root}:{os.environ['PATH']}",
                "CURL_LOG": str(log),
                "SCCAP_TRUSTED_CONTEXT": "true",
                "SCCAP_BASE_URL": "https://sccap.example",
                "SCCAP_TOKEN": "test-token",
                "SCCAP_PROVIDER": malicious,
                "SCCAP_COMMIT_SHA": malicious,
                "SCCAP_REF": "</etc/shadow",
                "SCCAP_REPOSITORY": malicious,
                "SCCAP_PROJECT": "</proc/self/environ",
                "SCCAP_FRAMEWORKS": malicious,
                "SCCAP_SCAN_TYPE": "</etc/hosts",
                "SCCAP_ARCHIVE": str(archive),
                "SCCAP_POLL_ATTEMPTS": "1",
                "SCCAP_POLL_SECONDS": "0",
            }
            completed = subprocess.run(
                ["sh", str(script)],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            arguments = log.read_text(encoding="utf-8").splitlines()
            expected_text = {
                f"provider={malicious}",
                f"commit_sha={malicious}",
                "ref=</etc/shadow",
                f"repository_slug={malicious}",
                "trusted_context=true",
                "project_name=</proc/self/environ",
                f"frameworks={malicious}",
                "scan_type=</etc/hosts",
            }
            for value in expected_text:
                index = arguments.index(value)
                self.assertEqual(arguments[index - 1], "--form-string")
            archive_value = f"archive_file=@{archive}"
            self.assertEqual(arguments[arguments.index(archive_value) - 1], "--form")


if __name__ == "__main__":
    unittest.main()
