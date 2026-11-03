import collections
import datetime
import ipaddress
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import load  # noqa: E402


class FakeResponse:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class LoadTests(unittest.TestCase):
    def test_addresses_are_ipv6_documentation_addresses(self):
        documentation = ipaddress.ip_network("2001:db8::/32")
        for index in (0, 1, 8191, 8192, 70000):
            self.assertIn(ipaddress.ip_address(load.address(index, 8192, 100000)), documentation)

    def test_offset_separates_loads(self):
        first = {load.address(i, 8192, 0) for i in range(8192)}
        second = {load.address(i, 8192, 8192) for i in range(8192)}
        self.assertEqual(8192, len(first))
        self.assertFalse(first & second)

    def test_bound_holds_for_every_bucket_of_a_backfill(self):
        rows, span, bucket, addresses = 100000, 120, 10, 2048
        start = datetime.datetime(2026, 11, 3, 6, 3, 17, tzinfo=datetime.timezone.utc)
        step = datetime.timedelta(minutes=span) / rows
        counts = collections.Counter()
        for i in range(rows):
            at = start + step * i
            minute = (at.hour * 60 + at.minute) // bucket
            counts[(load.address(i, addresses, 0), minute)] += 1
        bound = load.per_address_bound(rows * bucket / span, addresses)
        self.assertLessEqual(max(counts.values()), bound)

    def test_row_is_a_deny_the_firewall_rule_reads(self):
        at = datetime.datetime(2026, 11, 3, tzinfo=datetime.timezone.utc)
        row = load.row("load-x", 7, at, 16, 0, "lab")
        self.assertEqual(("network_connection_denied", "denied"), (row["eventType"], row["eventResult"]))
        self.assertEqual("load-x-000000007", row["eventId"])
        self.assertEqual("lab", row["collector"]["id"])
        self.assertLess(len(json.dumps(row, separators=(",", ":"))), 520)

    def test_an_early_expired_token_is_refreshed_once_and_the_batch_retried(self):
        # The live run lost its trickle to a 401: the CLI handed back a token near expiry.
        tokens = iter(['{"token": "t1", "expires": 9999999999}', '{"token": "t2", "expires": 9999999999}'])
        sent = []

        def urlopen(request, timeout):
            sent.append(request.get_header("Authorization"))
            if len(sent) == 1:
                raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)
            return FakeResponse()

        uploader = load.Uploader("https://example.invalid", "dcr-x")
        with mock.patch.object(load.subprocess, "run", side_effect=lambda *a, **k: mock.Mock(stdout=next(tokens))), \
                mock.patch.object(load.urllib.request, "urlopen", urlopen), mock.patch.object(load.time, "sleep"):
            uploader.send([{"eventId": "x"}])
        self.assertEqual(["Bearer t1", "Bearer t2"], sent)
        self.assertEqual((1, 1), (uploader.stats["rows"], uploader.stats["retries"]))

    def test_a_second_401_is_not_retried(self):
        def urlopen(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)

        uploader = load.Uploader("https://example.invalid", "dcr-x")
        token = mock.Mock(stdout='{"token": "t", "expires": 9999999999}')
        with mock.patch.object(load.subprocess, "run", return_value=token), \
                mock.patch.object(load.urllib.request, "urlopen", urlopen), mock.patch.object(load.time, "sleep"):
            with self.assertRaises(SystemExit):
                uploader.send([{"eventId": "x"}])

    def test_refuses_a_load_that_could_cross_the_threshold(self):
        with self.assertRaises(SystemExit) as raised:
            load.main(["backfill", "--endpoint", "https://example.invalid", "--dcr", "dcr-x", "--rows", "1000000",
                       "--addresses", "100", "--summary", os.devnull])
        self.assertIn("reach the threshold", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
