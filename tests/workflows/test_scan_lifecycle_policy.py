"""Unit contracts for the centralized scan lifecycle policy."""

import unittest

from app.infrastructure.messaging.publisher import ALLOWED_OUTBOX_KEYS
from app.shared.lib.scan_status import (
    ACTIVE_SCAN_STATUSES,
    ALL_SCAN_STATUSES,
    STATUS_ANALYZING_CONTEXT,
    STATUS_BLOCKED_PRE_LLM,
    STATUS_BLOCKED_USER_DECLINE,
    STATUS_BUDGET_EXHAUSTED,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_GENERATING_REPORTS,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_QUEUED,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_REMEDIATION_COMPLETED,
    STATUS_RUNNING_AGENTS,
    TERMINAL_SCAN_STATUSES,
    is_scan_status_transition_allowed,
)


class LifecycleDispatchContractTests(unittest.TestCase):
    def test_manual_run_control_routing_fields_survive_publisher_allowlist(
        self,
    ) -> None:
        self.assertTrue(
            {
                "action",
                "mode",
                "gate_id",
                "gate_version",
                "gate_sequence",
                "node_name",
                "evidence_hash",
            }.issubset(ALLOWED_OUTBOX_KEYS)
        )

    def test_terminal_statuses_have_no_normal_exit(self) -> None:
        for current in TERMINAL_SCAN_STATUSES:
            for target in ALL_SCAN_STATUSES - {current}:
                self.assertFalse(
                    is_scan_status_transition_allowed(current, target),
                    f"unexpected normal transition {current} -> {target}",
                )

    def test_manual_reset_is_the_only_declared_terminal_exit(self) -> None:
        self.assertTrue(
            is_scan_status_transition_allowed(STATUS_FAILED, STATUS_QUEUED, manual=True)
        )
        self.assertTrue(
            is_scan_status_transition_allowed(
                STATUS_CANCELLED, STATUS_QUEUED, manual=True
            )
        )
        self.assertFalse(
            is_scan_status_transition_allowed(
                STATUS_COMPLETED, STATUS_QUEUED, manual=True
            )
        )

    def test_policy_covers_all_gates_and_terminal_outcomes(self) -> None:
        for gate in (
            STATUS_PENDING_PRESCAN_APPROVAL,
            STATUS_PENDING_PROFILING_APPROVAL,
            STATUS_PENDING_APPROVAL,
        ):
            self.assertTrue(
                is_scan_status_transition_allowed(gate, STATUS_QUEUED_FOR_SCAN)
            )
            self.assertTrue(
                is_scan_status_transition_allowed(gate, STATUS_BLOCKED_USER_DECLINE)
            )

        for active in ACTIVE_SCAN_STATUSES:
            self.assertTrue(is_scan_status_transition_allowed(active, STATUS_FAILED))
            self.assertTrue(is_scan_status_transition_allowed(active, STATUS_CANCELLED))
            self.assertTrue(
                is_scan_status_transition_allowed(active, STATUS_BUDGET_EXHAUSTED)
            )

        self.assertIn(STATUS_BUDGET_EXHAUSTED, TERMINAL_SCAN_STATUSES)
        self.assertNotIn(STATUS_BUDGET_EXHAUSTED, ACTIVE_SCAN_STATUSES)
        self.assertFalse(
            is_scan_status_transition_allowed(
                STATUS_BUDGET_EXHAUSTED, STATUS_QUEUED, manual=True
            )
        )

        self.assertTrue(
            is_scan_status_transition_allowed(
                STATUS_PENDING_PRESCAN_APPROVAL, STATUS_BLOCKED_PRE_LLM
            )
        )
        self.assertTrue(
            is_scan_status_transition_allowed(
                STATUS_RUNNING_AGENTS, STATUS_GENERATING_REPORTS
            )
        )
        self.assertTrue(
            is_scan_status_transition_allowed(
                STATUS_GENERATING_REPORTS, STATUS_COMPLETED
            )
        )
        self.assertTrue(
            is_scan_status_transition_allowed(
                STATUS_GENERATING_REPORTS, STATUS_REMEDIATION_COMPLETED
            )
        )
        self.assertTrue(
            is_scan_status_transition_allowed(STATUS_QUEUED, STATUS_ANALYZING_CONTEXT)
        )


if __name__ == "__main__":
    unittest.main()
