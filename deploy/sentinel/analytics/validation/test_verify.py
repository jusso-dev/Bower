import datetime
import os
import sys
import subprocess
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import verify  # noqa: E402

UTC = datetime.timezone.utc


class TimeTests(unittest.TestCase):
    def test_parses_every_fraction_length_log_analytics_returns(self):
        # Seen live: trailing zeros trimmed ("40.84127Z"), 100 ns ("40.8412701Z"), none at all.
        cases = {
            "2026-11-03T06:11:40.84127Z": datetime.datetime(2026, 11, 3, 6, 11, 40, 841270, UTC),
            "2026-11-03T06:11:40.8412701Z": datetime.datetime(2026, 11, 3, 6, 11, 40, 841270, UTC),
            "2026-11-03T06:11:40.5Z": datetime.datetime(2026, 11, 3, 6, 11, 40, 500000, UTC),
            "2026-11-03T06:11:40Z": datetime.datetime(2026, 11, 3, 6, 11, 40, tzinfo=UTC),
        }
        for value, expected in cases.items():
            self.assertEqual(expected, verify._time(value), value)

    def test_does_not_touch_the_date(self):
        self.assertEqual(datetime.datetime(2026, 1, 2, 3, 4, 5, 6000, UTC), verify._time("2026-01-02T03:04:05.006Z"))


class IncidentTests(unittest.TestCase):
    def test_entities_fall_back_to_the_alerts_when_the_entities_api_fails(self):
        incident = {"id": "/ws/incidents/1", "properties": {"incidentNumber": 1, "title": "t", "additionalData": {"alertsCount": 1}}}

        def az_rest(method, url, body=None, resource=None):
            if url.endswith("incidents?api-version=" + verify.SENTINEL_API):
                return {"value": [incident]}
            if "/alerts?" in url:
                return {"value": [{"properties": {"systemAlertId": "a1"}}]}
            raise subprocess.CalledProcessError(1, "az")

        rows = [{"Kind": "ip", "Address": "198.51.100.21", "HostName": ""}]
        with mock.patch.object(verify, "az_rest", az_rest), mock.patch.object(verify, "query", return_value=rows) as query:
            found = verify.incidents("/ws", "workspace-id")
        self.assertEqual(["198.51.100.21"], found[0]["ipAddresses"])
        self.assertEqual("SecurityAlert.Entities", found[0]["entitySource"])
        self.assertIn('"a1"', query.call_args[0][1])


if __name__ == "__main__":
    unittest.main()
