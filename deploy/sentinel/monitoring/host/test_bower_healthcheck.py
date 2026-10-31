"""Tests for bower-healthcheck.py: python3 -B -m unittest discover -s deploy/sentinel/monitoring/host -v"""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location("healthcheck", Path(__file__).with_name("bower-healthcheck.py"))
healthcheck = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(healthcheck)

NOW = datetime(2026, 10, 31, 9, 0, 0, tzinfo=timezone.utc)
TOKEN = "test-token-never-printed"


def options(**overrides):
    values = dict(queue_max_bytes=10 * 1024 ** 3, backlog_warning_seconds=900, backlog_critical_seconds=3600,
                  storage_warning_percent=70.0, storage_critical_percent=90.0, file_warning_percent=70.0,
                  file_critical_percent=85.0, disk_warning_percent=20.0,
                  disk_critical_percent=10.0, refusal_window_seconds=900, token_file="token",
                  churn_warning_connections=5)
    values.update(overrides)
    return SimpleNamespace(**values)


def status(**overrides):
    value = {
        "status": "healthy",
        "queue": {"queued": 0, "retrying": 0, "uploading": 0, "deadLettered": 0, "undeliveredBytes": 0,
                  "oldestUndelivered": None},
        "intake": {"observedSince": "2026-10-31T08:00:00.1234567+00:00", "capacityRefusals": 0,
                   "privacyAlertRefusals": 0, "lastRefusalAt": None},
        "sources": [],
        "syslog": [],
        "windowsEventLog": [],
    }
    value.update(overrides)
    return value


def codes(findings):
    return [item["code"] for item in findings]


class EvaluateTests(unittest.TestCase):
    def test_healthy_collector_is_ok(self):
        verdict, findings, metrics, _ = healthcheck.evaluate(
            {"status": "healthy"}, status(), {"total": 100, "free": 50}, options(), {}, NOW)
        self.assertEqual(healthcheck.OK, verdict)
        self.assertEqual([], findings)
        self.assertEqual(1, metrics["bower_up"])
        self.assertEqual(50.0, metrics["bower_queue_volume_free_percent"])

    def test_unreachable_collector_is_critical(self):
        verdict, findings, metrics, _ = healthcheck.evaluate(None, None, None, options(), {}, NOW)
        self.assertEqual(healthcheck.CRITICAL, verdict)
        self.assertEqual(["collector-unreachable"], codes(findings))
        self.assertEqual(0, metrics["bower_up"])

    def test_backlog_storage_dead_letters_and_refusals(self):
        queue = {"queued": 10, "retrying": 2, "uploading": 0, "deadLettered": 3,
                 "undeliveredBytes": int(0.75 * 1024 ** 3),
                 "oldestUndelivered": (NOW - timedelta(seconds=1200)).isoformat().replace("+00:00", "Z")}
        intake = {"observedSince": "2026-10-31T08:00:00+00:00", "capacityRefusals": 4, "privacyAlertRefusals": 0,
                  "lastRefusalAt": "2026-10-31T08:58:00.1234567+00:00"}
        verdict, findings, metrics, _ = healthcheck.evaluate(
            {"status": "degraded"}, status(queue=queue, intake=intake), None, options(queue_max_bytes=1024 ** 3), {}, NOW)
        self.assertEqual(healthcheck.CRITICAL, verdict)
        self.assertEqual(["health-degraded", "dead-letters", "backlog", "queue-storage", "capacity-refusals"], codes(findings))
        self.assertEqual(1200, metrics["bower_queue_oldest_undelivered_age_seconds"])
        self.assertEqual(12, metrics["bower_queue_undelivered_events"])
        self.assertEqual(75.0, metrics["bower_queue_capacity_used_percent"])

    def test_old_refusal_is_not_reported(self):
        intake = {"observedSince": "2026-10-31T08:00:00+00:00", "capacityRefusals": 4, "privacyAlertRefusals": 0,
                  "lastRefusalAt": "2026-10-31T08:00:00Z"}
        verdict, findings, _, _ = healthcheck.evaluate({"status": "healthy"}, status(intake=intake), None, options(), {}, NOW)
        self.assertEqual(healthcheck.OK, verdict)
        self.assertEqual([], findings)

    def test_overdue_sources_and_windows_state(self):
        sources = [{"application": "nftables-firewall", "environment": "validation", "state": "silent"},
                   {"application": "windows-security", "environment": "production", "state": "active"}]
        windows = [{"id": "forwarded-security", "state": "winevt-access-denied", "readErrors": 1}]
        verdict, findings, metrics, _ = healthcheck.evaluate(
            {"status": "degraded"}, status(sources=sources, windowsEventLog=windows), None, options(), {}, NOW)
        self.assertEqual(healthcheck.CRITICAL, verdict)
        self.assertIn("source-overdue", codes(findings))
        self.assertIn("windows-event-log", codes(findings))
        self.assertEqual(1, metrics["bower_sources_overdue"])

    def test_syslog_errors_are_reported_only_when_new_in_the_same_process(self):
        listener = {"id": "firewall-tls", "tlsHandshakeFailures": 2, "connectionsAccepted": 9, "activeConnections": 1}
        current = status(syslog=[listener])
        _, _, _, state = healthcheck.evaluate({"status": "healthy"}, current, None, options(), {}, NOW)
        verdict, findings, _, _ = healthcheck.evaluate({"status": "healthy"}, current, None, options(), state, NOW)
        self.assertEqual(healthcheck.OK, verdict)
        worse = status(syslog=[dict(listener, tlsHandshakeFailures=5)])
        verdict, findings, metrics, _ = healthcheck.evaluate({"status": "healthy"}, worse, None, options(), state, NOW)
        self.assertEqual(healthcheck.WARNING, verdict)
        self.assertEqual(["syslog-errors"], codes(findings))
        self.assertIn("3 new", findings[0]["detail"])
        self.assertEqual(5, metrics['bower_syslog_errors_total{listener="firewall-tls"}'])
        # A restart resets counters: no comparison across processes.
        restarted = dict(worse, intake=dict(worse["intake"], observedSince="2026-10-31T08:59:00Z"))
        verdict, _, _, _ = healthcheck.evaluate({"status": "healthy"}, restarted, None, options(), state, NOW)
        self.assertEqual(healthcheck.OK, verdict)

    def test_connection_churn(self):
        listener = {"id": "firewall-tls", "connectionsAccepted": 3, "activeConnections": 1}
        _, _, _, state = healthcheck.evaluate({"status": "healthy"}, status(syslog=[listener]), None, options(), {}, NOW)
        churned = status(syslog=[dict(listener, connectionsAccepted=11)])
        verdict, findings, _, _ = healthcheck.evaluate({"status": "healthy"}, churned, None, options(), state, NOW)
        self.assertEqual(healthcheck.WARNING, verdict)
        self.assertEqual(["syslog-churn"], codes(findings))

    def test_queue_file_near_its_page_limit(self):
        limit = healthcheck.queue_file_limit(4 * 1024 ** 2)
        self.assertEqual(8 * 1024 ** 2, limit)
        verdict, findings, metrics, _ = healthcheck.evaluate(
            {"status": "healthy"}, status(), None, options(queue_max_bytes=4 * 1024 ** 2), {}, NOW, int(limit * 0.9))
        self.assertEqual(healthcheck.CRITICAL, verdict)
        self.assertEqual(["queue-file"], codes(findings))
        self.assertEqual(90.0, metrics["bower_queue_file_limit_used_percent"])

    def test_low_disk(self):
        verdict, findings, _, _ = healthcheck.evaluate(
            {"status": "healthy"}, status(), {"total": 100, "free": 5}, options(), {}, NOW)
        self.assertEqual(healthcheck.CRITICAL, verdict)
        self.assertEqual(["disk-free"], codes(findings))

    def test_unreadable_status_with_a_token_is_unknown(self):
        verdict, findings, _, _ = healthcheck.evaluate({"status": "healthy"}, None, None, options(), {}, NOW)
        self.assertEqual(healthcheck.UNKNOWN, verdict)
        self.assertEqual(["status-unavailable"], codes(findings))

    def test_parse_time_accepts_dotnet_precision_and_offsets(self):
        self.assertEqual(datetime(2026, 10, 31, 8, 34, 45, 223163, tzinfo=timezone.utc),
                         healthcheck.parse_time("2026-10-31T08:34:45.2231638+00:00"))
        self.assertEqual(datetime(2026, 10, 31, 8, 12, 52, 956280, tzinfo=timezone.utc),
                         healthcheck.parse_time("2026-10-31T08:12:52.95628Z"))
        self.assertEqual(timedelta(hours=10), healthcheck.parse_time("2026-10-31T18:00:00+10:00").utcoffset())
        self.assertIsNone(healthcheck.parse_time(None))

    def test_prometheus_text(self):
        text = healthcheck.prometheus({"bower_up": 1, 'bower_syslog_errors_total{listener="a"}': 2})
        self.assertIn("# TYPE bower_up gauge\nbower_up 1\n", text)
        self.assertIn('# TYPE bower_syslog_errors_total counter\nbower_syslog_errors_total{listener="a"} 2\n', text)


class Collector(BaseHTTPRequestHandler):
    body = {}

    def do_GET(self):  # noqa: N802 - http.server API
        if self.path == "/health":
            payload = {"status": "healthy"}
        elif self.path == "/v1/status" and self.headers.get("Authorization") == "Bearer " + TOKEN:
            payload = Collector.body
        else:
            self.send_response(401)
            self.end_headers()
            return
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class MainTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.directory = tempfile.TemporaryDirectory()
        self.token = os.path.join(self.directory.name, "token")
        Path(self.token).write_text(TOKEN + "\n", encoding="utf-8")
        Collector.body = status()

    def tearDown(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        self.directory.cleanup()

    def run_check(self, *extra):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = healthcheck.main(["--url", f"http://127.0.0.1:{self.server.server_port}", "--token-file", self.token,
                                     "--queue-path", self.directory.name, "--disk-warning-percent", "0",
                                     "--disk-critical-percent", "0", *extra])
        return code, output.getvalue()

    def test_reads_status_with_the_token_and_never_prints_it(self):
        Collector.body = status(queue=dict(status()["queue"], deadLettered=2))
        prometheus_file = os.path.join(self.directory.name, "bower.prom")
        code, output = self.run_check("--format", "json", "--prometheus-file", prometheus_file)
        self.assertEqual(healthcheck.WARNING, code)
        self.assertNotIn(TOKEN, output)
        self.assertEqual("WARNING", json.loads(output)["status"])
        self.assertIn("bower_queue_dead_lettered_events 2", Path(prometheus_file).read_text(encoding="utf-8"))

    def test_unreachable_collector(self):
        port = self.server.server_port
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = healthcheck.main(["--url", f"http://127.0.0.1:{port}", "--queue-path", self.directory.name,
                                     "--timeout", "1"])
        self.assertEqual(healthcheck.CRITICAL, code)
        self.assertTrue(output.getvalue().startswith("CRITICAL: collector-unreachable"))


if __name__ == "__main__":
    unittest.main()
