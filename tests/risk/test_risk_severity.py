import unittest

from app.shared.lib.risk_severity import risk_severity_for_score


class RiskSeverityForScoreTests(unittest.TestCase):
    def test_cvss_boundaries(self) -> None:
        cases = {
            0.0: "None",
            0.1: "Low",
            3.9: "Low",
            4.0: "Medium",
            6.9: "Medium",
            7.0: "High",
            8.9: "High",
            9.0: "Critical",
            10.0: "Critical",
        }
        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(risk_severity_for_score(score), expected)

    def test_clamps_out_of_range_values(self) -> None:
        self.assertEqual(risk_severity_for_score(-1), "None")
        self.assertEqual(risk_severity_for_score(99), "Critical")


if __name__ == "__main__":
    unittest.main()
