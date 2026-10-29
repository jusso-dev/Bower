"""Exercise the actual postrm script with isolated process/account command fakes."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class PackagePurgeTests(unittest.TestCase):
    def run_purge(self, failures):
        script = Path(__file__).resolve().parents[2] / 'deploy/installers/linux/scripts/postremove.sh'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = {
                'rm': 'exit 0',  # Never touch the machine running this test.
                'sleep': 'exit 0',
                'systemctl': 'exit 0',
                'getent': '[ "$1" = passwd ]',
                'userdel': '''[ "$#" -eq 1 ] && [ "$1" = bower ] || exit 99
count=0
[ ! -f "$TEST_STATE/count" ] || read -r count < "$TEST_STATE/count"
count=$((count + 1))
printf '%s\\n' "$count" > "$TEST_STATE/count"
[ "$count" -gt "$TEST_FAILURES" ]''',
            }
            for name, body in commands.items():
                executable = root / name
                executable.write_text('#!/bin/sh\n' + body + '\n', encoding='utf-8')
                executable.chmod(0o700)
            result = subprocess.run(['/bin/sh', str(script), 'purge'], env={
                **os.environ, 'PATH': directory, 'TEST_STATE': directory, 'TEST_FAILURES': str(failures),
            }, capture_output=True, text=True)
            return result, int((root / 'count').read_text())

    def test_account_removal_retries_transient_busy_process(self):
        result, attempts = self.run_purge(2)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(3, attempts)

    def test_persistent_account_failure_fails_purge_without_force(self):
        result, attempts = self.run_purge(100)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(30, attempts)
        self.assertIn('could not remove the service account', result.stderr)


if __name__ == '__main__':
    unittest.main()
