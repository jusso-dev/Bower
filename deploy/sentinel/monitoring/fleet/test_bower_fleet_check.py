"""Tests for bower-fleet-check.py: python3 -B -m unittest discover -s deploy/sentinel/monitoring/fleet -v"""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("fleetcheck", Path(__file__).with_name("bower-fleet-check.py"))
fleetcheck = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fleetcheck)


def collector(identifier, state, light):
    return {"id": identifier, "state": state, "light": light, "label": state, "reason": "fixed text",
            "lastSeenAt": "2026-10-31T09:00:00+00:00"}


class FleetCheckTests(unittest.TestCase):
    def test_healthy_fleet_is_ok(self):
        verdict, problems, metrics = fleetcheck.evaluate(
            {"collectors": [collector("a", "healthy", "green")],
             "states": [{"state": "healthy", "light": "green", "collectors": 1}]}, set())
        self.assertEqual(fleetcheck.OK, verdict)
        self.assertEqual([], problems)
        self.assertEqual(1, metrics['bower_fleet_collectors{state="healthy",light="green"}'])

    def test_worst_light_wins(self):
        verdict, problems, _ = fleetcheck.evaluate(
            {"collectors": [collector("a", "not-heard-from", "red"), collector("b", "cannot-deliver", "amber")]}, set())
        self.assertEqual(fleetcheck.CRITICAL, verdict)
        self.assertEqual(["a", "b"], [item["collector"] for item in problems])

    def test_ignored_states(self):
        verdict, problems, _ = fleetcheck.evaluate(
            {"collectors": [collector("a", "old-version", "amber"), collector("b", "removed", "none")]}, {"old-version"})
        self.assertEqual(fleetcheck.OK, verdict)
        self.assertEqual([], problems)


if __name__ == "__main__":
    unittest.main()
