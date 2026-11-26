"""A display refresh must not log like a write."""
import logging
import time

from app.shared.lib.risk_score import compute_cvss_aggregate


class _Finding:
    def __init__(self, severity="High", cvss=8.0):
        self.severity = severity
        self.cvss_score = cvss
        self.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.id = 1


def test_read_path_recompute_is_debug_not_info(caplog) -> None:
    findings = [_Finding() for _ in range(3)]
    with caplog.at_level(logging.DEBUG):
        compute_cvss_aggregate(findings, scan_id="scan", verbose=False)
    assert not [r for r in caplog.records if r.levelno == logging.INFO
                and "cvss aggregate" in r.getMessage()]
    assert [r for r in caplog.records if r.levelno == logging.DEBUG
            and "cvss aggregate" in r.getMessage()]


def test_persisting_a_score_still_logs_at_info(caplog) -> None:
    with caplog.at_level(logging.INFO):
        compute_cvss_aggregate([_Finding()], scan_id="scan")
    assert [r for r in caplog.records if r.levelno == logging.INFO
            and "cvss aggregate" in r.getMessage()]
