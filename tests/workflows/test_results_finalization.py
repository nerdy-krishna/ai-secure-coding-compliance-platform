"""Focused transaction contract for final scan persistence."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from app.infrastructure.workflows.nodes.results import save_final_report_node


class _SessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class FinalReportTransactionTests(unittest.IsolatedAsyncioTestCase):
    async def test_variance_and_terminal_writes_share_the_final_commit(self):
        scan_id = uuid4()
        start_session = SimpleNamespace()
        terminal_session = SimpleNamespace(
            commit=AsyncMock(),
            rollback=AsyncMock(),
        )
        attempt_session = SimpleNamespace(commit=AsyncMock())
        start_repo = SimpleNamespace(record_scan_event=AsyncMock(return_value=True))
        terminal_repo = SimpleNamespace(
            save_final_reports_and_status=AsyncMock(return_value=True),
            create_scan_event=AsyncMock(),
        )
        usage_repo = SimpleNamespace(measure_scan_estimate_variance=AsyncMock())
        governance_repo = SimpleNamespace(
            materialize_scan=AsyncMock(),
            evaluate_scan_policy=AsyncMock(),
        )
        release_budget = AsyncMock()

        with patch(
            "app.infrastructure.workflows.nodes.results.AsyncSessionLocal",
            side_effect=[
                _SessionContext(start_session),
                _SessionContext(terminal_session),
                _SessionContext(attempt_session),
            ],
        ), patch(
            "app.infrastructure.workflows.nodes.results.ScanRepository",
            side_effect=[start_repo, terminal_repo],
        ), patch(
            "app.infrastructure.workflows.nodes.results.LLMUsageRepository",
            return_value=usage_repo,
        ), patch(
            "app.infrastructure.workflows.nodes.results.FindingGovernanceRepository",
            return_value=governance_repo,
        ), patch(
            "app.infrastructure.workflows.nodes.results.release_scan_budget",
            new=release_budget,
        ), patch(
            "app.infrastructure.workflows.nodes.results._persist_finding_lineage_artifact",
            new=AsyncMock(),
        ), patch(
            "app.infrastructure.database.repositories.scan_attempt_repo.ScanAttemptRepository",
            return_value=SimpleNamespace(
                mark_current_terminal=AsyncMock(return_value=None)
            ),
        ):
            await save_final_report_node(
                {"scan_id": scan_id, "scan_type": "AUDIT", "findings": []}
            )

        usage_repo.measure_scan_estimate_variance.assert_awaited_once_with(
            scan_id=scan_id,
            stage="analysis",
            commit=False,
        )
        release_budget.assert_awaited_once_with(
            terminal_session, scan_id, reason="scan_completed"
        )
        governance_repo.materialize_scan.assert_awaited_once_with(
            scan_id, commit=False
        )
        governance_repo.evaluate_scan_policy.assert_awaited_once_with(
            scan_id, commit=False, idempotent=True
        )
        terminal_repo.save_final_reports_and_status.assert_awaited_once()
        self.assertFalse(
            terminal_repo.save_final_reports_and_status.await_args.kwargs["commit"]
        )
        terminal_session.commit.assert_awaited_once_with()
        terminal_session.rollback.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
