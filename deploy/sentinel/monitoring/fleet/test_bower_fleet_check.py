"""Tests for bower-fleet-check.py: python3 -B -m unittest discover -s deploy/sentinel/monitoring/fleet -v"""

import importlib.util
import contextlib
import io
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("fleetcheck", Path(__file__).with_name("bower-fleet-check.py"))
fleetcheck = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fleetcheck)


def collector(identifier, state, light):
    return {"id": identifier, "state": state, "light": light, "label": state, "reason": "fixed text",
            "lastSeenAt": "2026-10-31T09:00:00+00:00"}


class UrlSafetyTests(unittest.TestCase):
    def test_unsafe_url_never_opens_a_request(self):
        with patch.object(fleetcheck.urllib.request, "build_opener") as opener:
            self.assertEqual(fleetcheck.UNKNOWN, fleetcheck.main(["--url", "http://example.com"]))
            opener.assert_not_called()

    def test_urls_require_https_or_literal_loopback(self):
        for value in ("http://127.0.0.1:4319", "http://[::1]:4319", "https://example.com:443"):
            self.assertTrue(fleetcheck.safe_base_url(value), value)
        for value in ("http://example.com", "http://localhost", "http://127.1", "http://127.0.0.1.evil", "http://127.0.0.1@evil", "https://user@example.com", "https://example.com?x=y", "https://example.com\\@evil", "https://example.com:99999", "https://example.com\n.evil"):
            self.assertFalse(fleetcheck.safe_base_url(value), value)


class FleetCheckTests(unittest.TestCase):
    def test_untrusted_labels_and_text_are_escaped(self):
        verdict, problems, metrics = fleetcheck.evaluate(
            {"collectors": [collector('host"\\x\ninjected', 'bad"\nstate', "red")],
             "states": [{"state": 'bad"\nstate', "light": "red", "collectors": 1}]}, set())
        self.assertEqual(fleetcheck.CRITICAL, verdict)
        keys = " ".join(metrics)
        self.assertIn('host\\"\\\\x\\ninjected', keys)
        self.assertIn('bad\\"\\nstate', keys)
        self.assertNotIn("\n", keys)
        self.assertNotIn("\n", fleetcheck.text_value(problems[0]["collector"]))
        with self.assertRaises(ValueError):
            fleetcheck.evaluate({"collectors": [collector("a", "healthy", "green")],
                                 "states": [{"collectors": "1\ninjected 1"}]}, set())

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

    def test_only_removed_collectors_is_unknown(self):
        removed = collector("a", "removed", "none")
        verdict, problems, metrics = fleetcheck.evaluate({"collectors": [removed]}, set())
        self.assertEqual(fleetcheck.UNKNOWN, verdict)
        self.assertEqual("No active collectors", problems[0]["label"])
        self.assertEqual(fleetcheck.UNKNOWN, metrics["bower_fleet_check_status"])
        self.assertEqual(fleetcheck.UNKNOWN, fleetcheck.evaluate(
            {"collectors": [collector("a", "unexpected", "none")]}, set())[0])
        healthy = collector("b", "healthy", "green")
        self.assertEqual(fleetcheck.OK, fleetcheck.evaluate({"collectors": [removed, healthy]}, set())[0])
        red = collector("c", "cannot-deliver", "red")
        self.assertEqual(fleetcheck.CRITICAL, fleetcheck.evaluate({"collectors": [removed, red]}, set())[0])

    def test_ignored_states(self):
        verdict, problems, _ = fleetcheck.evaluate(
            {"collectors": [collector("a", "old-version", "amber"), collector("b", "removed", "none")]}, {"old-version"})
        self.assertEqual(fleetcheck.OK, verdict)
        self.assertEqual([], problems)

    def test_invalid_or_unknown_fleet_is_not_reported_healthy(self):
        for document in [{}, {"collectors": None}, {"collectors": [None]},
                         {"collectors": [collector("a", "healthy", "green")], "states": [None]}]:
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    fleetcheck.evaluate(document, set())
        unknown = collector("a", "new-state", "new-light")
        self.assertEqual(fleetcheck.UNKNOWN, fleetcheck.evaluate({"collectors": []}, set())[0])
        self.assertEqual(fleetcheck.UNKNOWN, fleetcheck.evaluate({"collectors": [unknown]}, set())[0])
        red = collector("b", "not-heard-from", "red")
        self.assertEqual(fleetcheck.CRITICAL, fleetcheck.evaluate({"collectors": [unknown, red]}, set())[0])

    def test_authenticated_redirect_is_not_followed(self):
        class Sink(BaseHTTPRequestHandler):
            requests = 0
            def do_GET(self):
                type(self).requests += 1
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                pass
        target = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_port}/stolen")
                self.end_headers()
            def log_message(self, *args):
                pass
        source = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=source.serve_forever, daemon=True).start()
        try:
            output = io.StringIO()
            with patch.dict(os.environ, {"BOWER_TEST_TOKEN": "synthetic-secret-marker"}), contextlib.redirect_stdout(output):
                result = fleetcheck.main(["--url", f"http://127.0.0.1:{source.server_port}", "--token-env", "BOWER_TEST_TOKEN"])
            self.assertEqual(fleetcheck.UNKNOWN, result)
            self.assertEqual(0, Sink.requests)
            self.assertNotIn("synthetic-secret-marker", output.getvalue())
            handler = fleetcheck.NoRedirect()
            request = fleetcheck.urllib.request.Request("https://collector.example/api/fleet")
            self.assertIsNone(handler.redirect_request(request, None, 302, "Found", {}, "http://other.example/"))
        finally:
            source.shutdown(); source.server_close()
            target.shutdown(); target.server_close()


if __name__ == "__main__":
    unittest.main()
