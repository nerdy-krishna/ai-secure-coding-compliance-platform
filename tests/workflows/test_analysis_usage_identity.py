import unittest

from app.shared.lib.analysis_envelope import build_analysis_usage_unit_key


class AnalysisUsageIdentityTests(unittest.TestCase):
    def test_chunk_and_lane_are_part_of_the_logical_call_identity(self) -> None:
        base = {
            "file_path": "src/app.py",
            "start_line": 1,
            "end_line": 100,
            "agent_name": "InjectionAgent",
            "llm_config_id": "config-1",
        }
        primary = build_analysis_usage_unit_key(**base, chunk_index=0, lane="primary")
        next_chunk = build_analysis_usage_unit_key(
            **base, chunk_index=1, lane="primary"
        )
        secondary = build_analysis_usage_unit_key(
            **base, chunk_index=0, lane="secondary"
        )

        self.assertEqual(len({primary, next_chunk, secondary}), 3)


if __name__ == "__main__":
    unittest.main()
