"""Local fixtures only: no real queue replay and no cloud calls."""

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import replay


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "queue with spaces.db"
        self.database.write_bytes(b"synthetic fixture, not a queue")
        self.cli = self.root / "fake compiled cli"
        self.audit = self.root / "audit"
        self.marker = self.root / "arguments.json"
        self.make_cli()

    def make_cli(self, exit_code=0, wait=False):
        self.cli.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys, time\n"
            f"intent = pathlib.Path({str(self.audit / 'intent.json')!r})\n"
            "assert json.loads(intent.read_text())['record_type'] == 'intent'\n"
            f"pathlib.Path({str(self.marker)!r}).write_text(json.dumps(sys.argv[1:]))\n"
            f"pathlib.Path({str(self.root / 'child.pid')!r}).write_text(str(os.getpid()))\n"
            "print('synthetic-secret-stdout')\n"
            "print('synthetic-secret-stderr', file=sys.stderr)\n"
            + ("time.sleep(30)\n" if wait else "")
            + f"sys.exit({exit_code})\n",
            encoding="utf-8",
        )
        self.cli.chmod(0o700)

    def arguments(self, events=None):
        values = ["--cli", str(self.cli), "--database", str(self.database),
                  "--audit-directory", str(self.audit), "--operator", "operator-17",
                  "--change-reference", "CHG-123"]
        for event in events if events is not None else ["reviewed-1", "reviewed:2"]:
            values.extend(["--event", event])
        return values

    def read(self, name):
        return json.loads((self.audit / name).read_text())

    def invoke(self, arguments=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = replay.main(arguments if arguments is not None else self.arguments())
        return result, output.getvalue()

    def test_success_exact_ids_bounded_array_and_metadata_only_audit(self):
        result, output = self.invoke()
        self.assertEqual(0, result)
        self.assertEqual(
            ["queue", "replay", "--database", str(self.database.resolve()), "--max", "2",
             "--event", "reviewed-1", "--event", "reviewed:2"],
            json.loads(self.marker.read_text()),
        )
        intent, outcome = self.read("intent.json"), self.read("outcome.json")
        self.assertEqual("operator-17", intent["operator"])
        self.assertEqual("CHG-123", intent["change_reference"])
        self.assertEqual(["reviewed-1", "reviewed:2"], intent["event_ids"])
        self.assertEqual(2, intent["maximum_count"])
        self.assertEqual(replay.file_digest(self.cli), intent["cli_file_sha256"])
        self.assertEqual(intent["operation_id"], outcome["operation_id"])
        self.assertEqual("cli-exit-zero", outcome["status"])
        self.assertEqual("unverified", outcome["queue_effect"])
        self.assertFalse(outcome["delivery_verified"])
        self.assertEqual(0o700, self.audit.stat().st_mode & 0o777)
        for path in self.audit.iterdir():
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
        audit_text = "".join(path.read_text() for path in self.audit.iterdir())
        self.assertNotIn("synthetic-secret", audit_text + output)
        self.assertNotIn(str(self.database), audit_text)
        self.assertNotIn(str(self.cli), audit_text)

    def test_nonzero_exit_is_ambiguous_and_suppresses_all_cli_output(self):
        self.make_cli(exit_code=17)
        result, output = self.invoke()
        self.assertEqual(1, result)
        outcome = self.read("outcome.json")
        self.assertEqual("cli-exit-nonzero", outcome["status"])
        self.assertEqual(17, outcome["cli_exit_code"])
        self.assertEqual("ambiguous", outcome["queue_effect"])
        self.assertNotIn("synthetic-secret", json.dumps(outcome) + output)

    def test_intent_is_durable_before_invocation_and_existing_directory_is_refused(self):
        real_fsync = os.fsync
        with mock.patch.object(replay.os, "fsync", wraps=real_fsync) as sync:
            def run(command, **kwargs):
                self.assertGreaterEqual(sync.call_count, 4)
                self.assertTrue((self.audit / "intent.json").is_file())
                self.assertFalse(kwargs["shell"])
                self.assertEqual(subprocess.DEVNULL, kwargs["stdout"])
                self.assertEqual(subprocess.DEVNULL, kwargs["stderr"])
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(replay.subprocess, "run", side_effect=run) as runner:
                self.assertEqual(0, self.invoke()[0])
                runner.assert_called_once()
        before = (self.audit / "intent.json").read_bytes()
        with mock.patch.object(replay.subprocess, "run") as runner:
            self.assertEqual(2, self.invoke()[0])
            runner.assert_not_called()
        self.assertEqual(before, (self.audit / "intent.json").read_bytes())

    def test_intent_sync_failure_at_each_boundary_prevents_invocation(self):
        real_fsync = os.fsync
        for boundary in range(1, 5):
            with self.subTest(boundary=boundary):
                self.audit = self.root / f"failed-{boundary}"
                calls = 0

                def sync(descriptor):
                    nonlocal calls
                    calls += 1
                    if calls == boundary:
                        raise OSError("synthetic-secret-filesystem-error")
                    real_fsync(descriptor)

                with mock.patch.object(replay.os, "fsync", side_effect=sync), \
                        mock.patch.object(replay.subprocess, "run") as runner:
                    result, output = self.invoke()
                self.assertEqual(2, result)
                runner.assert_not_called()
                self.assertNotIn("synthetic-secret", output)
                self.assertTrue(self.audit.exists())

    def test_outcome_audit_failure_preserves_intent_and_refuses_retry(self):
        persist = replay.persist

        def fail_outcome(directory, name, record):
            if name == "outcome.json":
                raise OSError("synthetic-secret-disk-full")
            persist(directory, name, record)

        with mock.patch.object(replay, "persist", side_effect=fail_outcome):
            result, output = self.invoke()
        self.assertEqual(2, result)
        self.assertIn("reconcile-before-any-retry", output)
        self.assertNotIn("synthetic-secret", output)
        self.assertTrue(self.marker.exists())
        self.assertTrue((self.audit / "intent.json").exists())
        self.assertFalse((self.audit / "outcome.json").exists())
        with mock.patch.object(replay.subprocess, "run") as runner:
            self.assertEqual(2, self.invoke()[0])
            runner.assert_not_called()

    def test_partial_outcome_sync_failure_never_reports_success(self):
        real_fsync = os.fsync
        for boundary in range(5, 8):
            with self.subTest(boundary=boundary):
                self.audit = self.root / f"outcome-failed-{boundary}"
                calls = 0

                def sync(descriptor):
                    nonlocal calls
                    calls += 1
                    if calls == boundary:
                        raise OSError("synthetic-secret-sync-failure")
                    real_fsync(descriptor)

                with mock.patch.object(replay.os, "fsync", side_effect=sync), \
                        mock.patch.object(replay.subprocess, "run",
                                          return_value=subprocess.CompletedProcess([], 0)) as runner:
                    result, output = self.invoke()
                self.assertEqual(2, result)
                runner.assert_called_once()
                self.assertIn("reconcile-before-any-retry", output)
                self.assertNotIn("synthetic-secret", output)
                self.assertTrue((self.audit / "intent.json").exists())
                self.assertTrue((self.audit / "outcome.json.pending").exists()
                                or (self.audit / "outcome.json").exists())
                with mock.patch.object(replay.subprocess, "run") as retry:
                    self.assertEqual(2, self.invoke()[0])
                    retry.assert_not_called()

    def test_timeout_kills_child_and_records_ambiguous_outcome(self):
        self.make_cli(wait=True)
        result, _ = self.invoke(self.arguments() + ["--timeout-seconds", "1"])
        self.assertEqual(1, result)
        outcome = self.read("outcome.json")
        self.assertEqual("timeout", outcome["status"])
        self.assertEqual("ambiguous", outcome["queue_effect"])
        with self.assertRaises(ProcessLookupError):
            os.kill(int((self.root / "child.pid").read_text()), 0)

    def test_launch_failure_and_interrupt_use_fixed_status_only(self):
        for error, status in [(OSError("synthetic-secret-os-error"), "launch-failed"),
                              (KeyboardInterrupt(), "interrupted")]:
            with self.subTest(status=status):
                self.audit = self.root / status
                with mock.patch.object(replay.subprocess, "run", side_effect=error):
                    result, output = self.invoke()
                self.assertEqual(1, result)
                outcome = self.read("outcome.json")
                self.assertEqual(status, outcome["status"])
                self.assertEqual("ambiguous", outcome["queue_effect"])
                self.assertNotIn("synthetic-secret", json.dumps(outcome) + output)

    def test_bounds_and_option_injection_fail_before_audit_or_invocation(self):
        invalid = [[], ["a"] * 2, [f"event-{i}" for i in range(101)], ["a" * 129],
                   [""], ["--code"], ["a\nb"], ["a;touch"], ["$(id)"], ["é"], ["*"]]
        for events in invalid:
            with self.subTest(events=events), mock.patch.object(replay.subprocess, "run") as runner:
                result, _ = self.invoke(self.arguments(events))
                self.assertEqual(2, result)
                runner.assert_not_called()
                self.assertFalse(self.audit.exists())
        for option, value in [("--operator", "a" * 81), ("--operator", ""),
                              ("--change-reference", "bad\nmetadata"),
                              ("--change-reference", ""), ("--timeout-seconds", "0"),
                              ("--timeout-seconds", "301"), ("--code", "azure-http")]:
            with self.subTest(option=option, value=value), \
                    mock.patch.object(replay.subprocess, "run") as runner:
                result, output = self.invoke(self.arguments() + [option, value])
                self.assertEqual(2, result)
                runner.assert_not_called()
                if value:
                    self.assertNotIn(value, output)

    def test_missing_metadata_and_unknown_arguments_do_not_echo_input(self):
        for option in ("--operator", "--change-reference"):
            arguments = self.arguments()
            index = arguments.index(option)
            del arguments[index:index + 2]
            self.assertEqual(2, self.invoke(arguments)[0])
        result, output = self.invoke(self.arguments() + ["--synthetic-secret-option"])
        self.assertEqual(2, result)
        self.assertNotIn("synthetic-secret", output)

    def test_maximum_batch_and_identifier_lengths_are_accepted(self):
        arguments = self.arguments(["a" * 128] + [f"event-{i}" for i in range(99)])
        self.assertEqual(0, self.invoke(arguments + ["--operator", "a" * 80,
                                                   "--change-reference", "b" * 80])[0])
        self.assertEqual(100, self.read("intent.json")["maximum_count"])

    def test_insecure_parent_and_symlink_audit_directory_are_refused(self):
        parent = self.root / "public"
        parent.mkdir(mode=0o755)
        self.audit = parent / "audit"
        self.assertEqual(2, self.invoke()[0])
        self.assertFalse(self.marker.exists())
        self.audit = self.root / "link"
        self.audit.symlink_to(parent, target_is_directory=True)
        self.assertEqual(2, self.invoke()[0])
        self.assertEqual([], list(parent.iterdir()))

    def test_sigkill_retains_intent_no_outcome_and_cannot_resume(self):
        self.make_cli(wait=True)
        process = subprocess.Popen([sys.executable, "-B", str(Path(replay.__file__)), *self.arguments()],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "child.pid").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue((self.root / "child.pid").exists())
            process.kill()
            process.wait(timeout=5)
            self.assertEqual(["reviewed-1", "reviewed:2"], self.read("intent.json")["event_ids"])
            self.assertFalse((self.audit / "outcome.json").exists())
            with mock.patch.object(replay.subprocess, "run") as runner:
                self.assertEqual(2, self.invoke()[0])
                runner.assert_not_called()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            pid_file = self.root / "child.pid"
            if pid_file.exists():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
