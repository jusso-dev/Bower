"""Unit tests for Microsoft Sentinel Content Hub packaging and validation."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_solution
import validate_sentinel


class SentinelPackagingTests(unittest.TestCase):
    def test_duration_to_iso8601(self):
        self.assertEqual(build_solution.duration_to_iso8601("5m"), "PT5M")
        self.assertEqual(build_solution.duration_to_iso8601("450m"), "PT450M")
        self.assertEqual(build_solution.duration_to_iso8601("1h"), "PT1H")
        self.assertEqual(build_solution.duration_to_iso8601("14d"), "P14D")
        self.assertEqual(build_solution.duration_to_iso8601("PT5H"), "PT5H")
        with self.assertRaises(ValueError):
            build_solution.duration_to_iso8601("5w")

    def test_kql_sanity_accepts_valid_queries_and_rejects_broken_ones(self):
        self.assertEqual([], validate_sentinel.check_kql_syntax("BowerSecurityEvents | take 10", "ok"))
        self.assertTrue(validate_sentinel.check_kql_syntax("BowerSecurityEvents | where (x == 1", "unclosed"))
        self.assertTrue(validate_sentinel.check_kql_syntax("| where x == 1", "leading-pipe"))
        self.assertTrue(validate_sentinel.check_kql_syntax("BowerSecurityEvents |", "trailing-pipe"))
        self.assertTrue(validate_sentinel.check_kql_syntax("let x = __MISSING__;", "placeholder"))
        self.assertEqual(
            [],
            validate_sentinel.check_kql_syntax("let x = __MISSING__;", "placeholder-allowed", allow_placeholders=True),
        )

    def test_solution_validates_end_to_end(self):
        self.assertEqual([], validate_sentinel.validate_solution())


if __name__ == "__main__":
    unittest.main()
