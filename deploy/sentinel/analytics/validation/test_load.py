import argparse
import collections
import datetime
import email.utils
import ipaddress
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import load  # noqa: E402


# The deployed rule's values, as the guide's command passes them.
RULE = ["--threshold", "20", "--bucket-minutes", "10"]
ENDPOINT = ["--endpoint", "https://example.invalid", "--dcr", "dcr-x"]


class FakeClock:
    """time.monotonic and time.sleep for the trickle loop, without waiting."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


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

    def test_refuses_a_slow_trickle_that_sends_more_than_its_rate(self):
        # Council finding: rate 0.01/s still sends one event every 30 s, 20 per 10-minute
        # bucket, which reaches the threshold although rate x bucket is 6.
        with self.assertRaises(SystemExit) as raised:
            load.main(["trickle", "--endpoint", "https://example.invalid", "--dcr", "dcr-x", "--rate", "0.01",
                       "--addresses", "1", "--duration-minutes", "10", *RULE, "--summary", os.devnull])
        self.assertIn("reach the threshold", str(raised.exception))

    def test_trickle_bound_covers_every_bucket_at_the_fastest_cadence(self):
        for rate, batch in ((0.01, 2000), (0.5, 300), (10, 300), (10, 2000), (400, 2000)):
            args = argparse.Namespace(mode="trickle", rate=rate, batch=batch, bucket_minutes=10)
            tick, count = load.trickle_plan(rate, batch)
            for offset in (0.0, 0.3, tick - 0.01):
                # Requests exactly `tick` apart, the fastest the loop sends.
                buckets = collections.Counter(int((offset + n * tick) // 600) for n in range(int(3 * 3600 / tick)))
                self.assertLessEqual(max(buckets.values()) * count, load.events_per_bucket(args), (rate, batch, offset))

    def test_the_live_run_settings_stay_accepted(self):
        backfill = argparse.Namespace(mode="backfill", rows=600000, span_minutes=120, bucket_minutes=10)
        trickle = argparse.Namespace(mode="trickle", rate=10, batch=300, bucket_minutes=10)
        self.assertLess(load.per_address_bound(load.events_per_bucket(backfill), 8192), 20)
        self.assertLess(load.per_address_bound(load.events_per_bucket(trickle), 8192), 20)

    def test_retry_after_accepts_seconds_and_http_dates(self):
        self.assertEqual(5.0, load.retry_after("5", 99))
        self.assertEqual(0.0, load.retry_after("-3", 99))
        self.assertEqual(99, load.retry_after(None, 99))
        self.assertEqual(99, load.retry_after("soon", 99))
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)
        self.assertAlmostEqual(120, load.retry_after(email.utils.format_datetime(later, usegmt=True), 99), delta=3)
        earlier = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=120)
        self.assertEqual(0.0, load.retry_after(email.utils.format_datetime(earlier, usegmt=True), 99))

    def test_refuses_a_load_that_could_cross_the_threshold(self):
        with self.assertRaises(SystemExit) as raised:
            load.main(["backfill", "--endpoint", "https://example.invalid", "--dcr", "dcr-x", "--rows", "1000000",
                       "--addresses", "100", *RULE, "--summary", os.devnull])
        self.assertIn("reach the threshold", str(raised.exception))



class GuardTests(unittest.TestCase):
    def refused(self, *arguments):
        with mock.patch.object(load.Uploader, "send") as send, self.assertRaises(SystemExit) as raised:
            load.main([*arguments, "--summary", os.devnull])
        send.assert_not_called()
        return str(raised.exception)

    def test_rejects_non_positive_addresses_before_the_bound(self):
        # A negative count made the bound negative, so the threshold check never refused.
        for addresses in ("0", "-1", "-5"):
            message = self.refused("backfill", *ENDPOINT, "--rows", "1000000", "--addresses", addresses, *RULE)
            self.assertIn("--addresses must be at least 1", message)

    def test_requires_the_deployed_threshold_and_bucket(self):
        self.refused("backfill", *ENDPOINT, "--rows", "10")
        self.assertIn("template minimum", self.refused("backfill", *ENDPOINT, "--rows", "10", "--threshold", "1",
                                                       "--bucket-minutes", "10"))
        self.assertIn("template range", self.refused("backfill", *ENDPOINT, "--rows", "10", "--threshold", "20",
                                                     "--bucket-minutes", "90"))

    def test_a_larger_deployed_bucket_is_checked_with_its_own_size(self):
        # 60,000 rows over 2 h and 819 addresses: 8 per address in a 10-minute bucket, but
        # 38 in a 60-minute one, which reaches a threshold of 20.
        args = ["backfill", *ENDPOINT, "--rows", "60000", "--span-minutes", "120", "--addresses", "819",
                "--threshold", "20"]
        self.assertIn("reach the threshold", self.refused(*args, "--bucket-minutes", "60"))
        with mock.patch.object(load.Uploader, "send"), tempfile.TemporaryDirectory() as directory:
            load.main([*args, "--bucket-minutes", "10", "--summary", os.path.join(directory, "s.json")])

    def test_rejects_empty_runs(self):
        self.assertIn("--rows", self.refused("backfill", *ENDPOINT, *RULE))
        self.assertIn("--rate", self.refused("trickle", *ENDPOINT, "--duration-minutes", "1", *RULE))
        self.assertIn("--duration-minutes", self.refused("trickle", *ENDPOINT, "--rate", "1", *RULE))


class RunTests(unittest.TestCase):
    def trickle(self, *arguments, addresses="100000"):
        clock, sent = FakeClock(), []
        with mock.patch.object(load.time, "monotonic", clock.monotonic), mock.patch.object(load.time, "sleep", clock.sleep), \
                mock.patch.object(load.Uploader, "send", lambda self, rows: sent.append(len(rows))), \
                tempfile.TemporaryDirectory() as directory:
            started = clock.now
            load.main(["trickle", *ENDPOINT, *arguments, "--addresses", addresses, *RULE,
                       "--summary", os.path.join(directory, "s.json")])
            return sent, clock.now - started

    def test_trickle_stops_at_its_deadline(self):
        # Before: a 6-second run with a 20-second tick sent 2,000 events and ran 20 s.
        sent, seconds = self.trickle("--rate", "100", "--duration-minutes", "0.1")
        self.assertEqual(600, sum(sent))
        self.assertAlmostEqual(6.0, seconds)

    def test_trickle_splits_requests_at_the_batch_size(self):
        # Before: --rate 10000 sent 10,000 rows (about 4.9 MB) in one request.
        sent, _ = self.trickle("--rate", "10000", "--duration-minutes", "0.05", "--batch", "2000",
                               addresses="1000000")
        self.assertLessEqual(max(sent), 2000)
        self.assertEqual(30000, sum(sent))

    def test_summary_path_is_opened_before_any_upload(self):
        with mock.patch.object(load.Uploader, "send") as send, self.assertRaises(OSError):
            load.main(["backfill", *ENDPOINT, "--rows", "10", *RULE, "--summary", "/nonexistent-dir/s.json"])
        send.assert_not_called()

    def test_helpers(self):
        self.assertEqual([2000, 2000, 1], load.chunks(4001, 2000))
        self.assertEqual((20.0, 2000), load.trickle_step(100, 20.0, 50.0))
        self.assertEqual((6.0, 600), load.trickle_step(100, 20.0, 6.0))
        self.assertEqual((0.0, 1), load.trickle_step(100, 20.0, -1.0))


if __name__ == "__main__":
    unittest.main()
