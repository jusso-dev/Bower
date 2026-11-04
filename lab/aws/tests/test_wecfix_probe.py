"""Real SQLite queue-union integration, enabled with BOWER_WECFIX_PROBE_DLL."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest


DLL = os.environ.get('BOWER_WECFIX_PROBE_DLL')
DOTNET = os.environ.get('BOWER_WECFIX_DOTNET', 'dotnet')


@unittest.skipUnless(DLL, 'set BOWER_WECFIX_PROBE_DLL to run the compiled lab probe')
class WecfixProbeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.database = self.root / 'queue.db'
        self.union = self.root / 'union.tsv'
        self.summary = self.root / 'summary.json'
        with sqlite3.connect(self.database) as connection:
            connection.execute('CREATE TABLE queue_events_v5 (event_id TEXT, state INTEGER, received_at TEXT, payload TEXT)')
            rows = [
                ('winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '2026-01-01T11:15:30.1234567+11:00', 'sensitive-marker-1'),
                ('winevt-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '2026-01-01T00:15:30Z', 'sensitive-marker-2'),
                ('winevt-ffffffffffffffffffffffffffffffff', '2026-01-01T00:15:30', 'sensitive-marker-3'),
                ('winevt-22222222222222222222222222222222', 'invalid\nsecret-marker-4', 'sensitive-marker-4'),
                ('winevt-11111111111111111111111111111111', '2026-01-01T00:15:30Z\n', 'sensitive-marker-5'),
            ]
            for event_id, generated, sensitive in rows:
                payload = json.dumps({'timeGenerated': generated, 'private': sensitive})
                connection.execute('INSERT INTO queue_events_v5 VALUES (?, 0, ?, ?)',
                                   (event_id, '2026-01-01T01:00:00Z', payload))
            connection.execute('INSERT INTO queue_events_v5 VALUES (?, 0, ?, ?)',
                               ('winevt-dddddddddddddddddddddddddddddddd', '2026-01-01T01:00:00Z',
                                '{"timeGenerated":"2026-01-01T00:00:00Z",'
                                '"timeGenerated":"2026-01-02T00:00:00Z"}'))
        self.union.write_text('winevt-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z\n'
                              'winevt-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z\n')

    def run_probe(self):
        return subprocess.run([DOTNET, DLL, 'queue-union', str(self.database), str(self.union), str(self.summary)],
                              capture_output=True, text=True, timeout=60)

    def test_receiving_position_rejects_unknown_channel_without_echoing_it(self):
        result = subprocess.run([DOTNET, DLL, 'receiving-position', 'secret-unapproved-channel'],
                                capture_output=True, text=True, timeout=60)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('secret-unapproved-channel', result.stdout + result.stderr)

    def test_exports_only_valid_normalized_time_and_enriches_retained_legacy_row(self):
        result = self.run_probe()
        self.assertEqual(0, result.returncode, result.stderr)
        rows = dict((parts[0], parts[1:]) for parts in
                    (line.split('\t') for line in self.union.read_text().splitlines()))
        self.assertEqual('2026-01-01T00:15:30.1234567+00:00', rows['winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'][2])
        self.assertEqual(['2026-01-01T02:00:00Z', '2026-01-01T01:00:00Z',
                          '2026-01-01T00:15:30.0000000+00:00'], rows['winevt-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'])
        self.assertEqual(2, len(rows['winevt-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee']))
        for event_id in ('winevt-ffffffffffffffffffffffffffffffff', 'winevt-22222222222222222222222222222222', 'winevt-11111111111111111111111111111111', 'winevt-dddddddddddddddddddddddddddddddd'):
            self.assertEqual('', rows[event_id][2])
        combined = result.stdout + result.stderr + self.union.read_text() + self.summary.read_text()
        self.assertNotIn('sensitive-marker', combined)
        self.assertNotIn('secret-marker', combined)

    def test_conflicting_retained_identity_fails_without_replacing_union(self):
        original = ('winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z\t'
                    '2026-01-01T00:00:00.0000000+00:00\n')
        self.union.write_text(original)
        result = self.run_probe()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(original, self.union.read_text())
        self.assertNotIn('sensitive-marker', result.stderr)

    def test_conflicting_duplicate_union_identity_fails_closed(self):
        original = ('winevt-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z\t2026-01-01T00:00:00Z\n'
                    'winevt-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z\t2026-01-01T00:00:01Z\n')
        self.union.write_text(original)
        result = self.run_probe()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(original, self.union.read_text())

    def test_bare_cr_in_existing_union_fails_without_replacing_file(self):
        first = 'winevt-' + 'e' * 32 + '\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z'
        second = 'winevt-' + 'f' * 32 + '\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z'
        for content in ((first + '\r' + second + '\n').encode(), (first + '\r').encode()):
            with self.subTest(content=content):
                self.union.write_bytes(content)
                result = self.run_probe()
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(content, self.union.read_bytes())

    def test_existing_union_accepts_lf_and_crlf(self):
        first = 'winevt-' + 'e' * 32 + '\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z'
        second = 'winevt-' + 'f' * 32 + '\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z'
        self.union.write_bytes((first + '\r\n' + second + '\n').encode())
        result = self.run_probe()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(first, self.union.read_text())
        self.assertIn(second, self.union.read_text())

    def test_crlf_split_across_read_buffer_is_accepted(self):
        timestamp = '2026-01-01T02:00:00Z'
        repeated = 'other\t' + timestamp + '\n'
        for count in range(400):
            id_length = 8191 - len(repeated) * count - len(timestamp) - 1
            if 1 <= id_length <= 128:
                break
        else:
            self.fail('could not construct boundary case')
        content = repeated * count + 'x' * id_length + '\t' + timestamp + '\r\n'
        self.assertEqual(8191, content.index('\r'))
        self.union.write_bytes(content.encode())
        result = self.run_probe()
        self.assertEqual(0, result.returncode, result.stderr)

    def test_invalid_identity_cannot_inject_tsv_rows(self):
        original = self.union.read_text()
        for bad in ('winevt-invalid', 'winevt-' + 'a' * 32 + '\tfake',
                    'other\nwinevt-' + 'b' * 32, 'other\u2028winevt-' + 'b' * 32,
                    'other\u2029winevt-' + 'b' * 32):
            with self.subTest(bad=bad):
                with sqlite3.connect(self.database) as connection:
                    connection.execute('INSERT INTO queue_events_v5 VALUES (?, 0, ?, ?)',
                                       (bad, '2026-01-01T01:00:00Z', '{}'))
                result = self.run_probe()
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(original, self.union.read_text())
                with sqlite3.connect(self.database) as connection:
                    connection.execute('DELETE FROM queue_events_v5 WHERE event_id = ?', (bad,))

    def test_invalid_receipt_time_cannot_inject_tsv_rows(self):
        original = self.union.read_text()
        with sqlite3.connect(self.database) as connection:
            connection.execute('UPDATE queue_events_v5 SET received_at = ? WHERE event_id = ?',
                               ('2026-01-01T01:00:00Z\ninjected', 'winevt-' + 'a' * 32))
        result = self.run_probe()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(original, self.union.read_text())

    def test_nonempty_invalid_generation_time_in_union_fails_closed(self):
        for timestamp in ('invalid', '2026-01-01T00:00:00Z\x00', '2026-01-01T00:00:00Z\u2028'):
            with self.subTest(timestamp=timestamp):
                content = ('winevt-' + 'e' * 32 + '\t2026-01-01T02:00:00Z\t2026-01-01T01:00:00Z\t'
                           + timestamp + '\n').encode()
                self.union.write_bytes(content)
                result = self.run_probe()
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(content, self.union.read_bytes())


if __name__ == '__main__':
    unittest.main()
