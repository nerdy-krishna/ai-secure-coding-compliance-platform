import unittest

from app.shared.lib.approval_policy import (
    is_strict_approval,
    requires_dual_cost_approval,
)


class CostApprovalPolicyTests(unittest.TestCase):
    def test_uses_the_persisted_total_cost_field(self) -> None:
        self.assertFalse(requires_dual_cost_approval({"total_estimated_cost": 49.99}))
        self.assertTrue(requires_dual_cost_approval({"total_estimated_cost": 50.0}))
        self.assertFalse(requires_dual_cost_approval({"estimated_cost_usd": 500.0}))

    def test_conservative_upper_bound_controls_dual_approval(self) -> None:
        self.assertTrue(
            requires_dual_cost_approval(
                {
                    "total_estimated_cost": 20.0,
                    "upper_bound_estimated_cost": 50.0,
                }
            )
        )

    def test_approval_requires_literal_true(self) -> None:
        self.assertTrue(is_strict_approval({"approved": True}))
        self.assertFalse(is_strict_approval({"approved": False}))
        self.assertFalse(is_strict_approval({"approved": 1}))
        self.assertFalse(is_strict_approval({}))


if __name__ == "__main__":
    unittest.main()
