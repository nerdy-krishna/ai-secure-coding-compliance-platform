"""Regression tests for persisted native scanner-report size bounds."""

from __future__ import annotations

import unittest

from app.infrastructure.scanners.report_artifact import (
    MAX_NATIVE_REPORT_BYTES,
    bounded_native_report,
    scanner_completion_status,
)


class ScannerReportBoundsTests(unittest.TestCase):
    def test_small_native_report_is_preserved(self) -> None:
        payload = {"results": [{"check_id": "python.sql-injection"}]}
        self.assertIs(bounded_native_report(payload), payload)

    def test_oversized_native_report_is_replaced_by_manifest(self) -> None:
        payload = {"results": "x" * (MAX_NATIVE_REPORT_BYTES + 1)}
        bounded = bounded_native_report(payload)
        self.assertTrue(bounded["truncated"])
        self.assertEqual(bounded["reason"], "native_report_exceeded_5_mib_limit")
        self.assertGreater(bounded["original_bytes"], MAX_NATIVE_REPORT_BYTES)

    def test_completion_status_distinguishes_skips_and_missing_reports(self) -> None:
        self.assertEqual(scanner_completion_status(False, False), "skipped")
        self.assertEqual(scanner_completion_status(True, False), "degraded")
        self.assertEqual(scanner_completion_status(True, True), "completed")


if __name__ == "__main__":
    unittest.main()
