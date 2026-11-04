import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / 'wecfix' / 'reconcile.py'
spec = importlib.util.spec_from_file_location('wecfix_reconcile', SCRIPT)
reconcile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reconcile)


class WecfixReconciliationTests(unittest.TestCase):
    def test_partial_destination_p99_is_only_an_observed_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            a, b = 'winevt-' + 'a' * 32, 'winevt-' + 'b' * 32
            (host / 'accepted.tsv').write_text(''.join(
                event_id + '\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t2026-01-01T00:00:04Z\n'
                for event_id in (a, b)))
            (host / 'samples.jsonl').write_text('')
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            windows = [{'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T00:01:00Z'}]
            output = Path(directory) / 'result.json'
            argv = ['reconcile.py', '--lab-dir', str(lab), '--start', str(start), '--end', str(start + 60),
                    '--collector', 'Wec=collector', '--out', str(output)]
            with mock.patch('sys.argv', argv), mock.patch.object(reconcile, 'Verifier'), \
                    mock.patch.object(reconcile, 'native', return_value=({a, b}, windows)), \
                    mock.patch.object(reconcile, 'sentinel', return_value=({a: {'Copies': 1}}, [],
                        {'p99': 1, 'count': 1, 'negativeSamples': 0}, [])), redirect_stdout(io.StringIO()):
                reconcile.main()
            collector = json.loads(output.read_text())['collectors']['Wec']
            self.assertTrue(collector['observedSampleP99WithinLimit'])
            self.assertIsNone(collector['latencyPassesPilotLimit'])
            self.assertIn('workload-coverage-unproven', collector['latencyQualificationProblems'])
            self.assertIn('destination-completeness-unproven', collector['latencyQualificationProblems'])
            self.assertIn('expected-events-missing-from-destination', collector['latencyQualificationProblems'])

    def test_bad_process_shape_is_reported_as_invalid_sampling(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            event_id = 'winevt-' + 'a' * 32
            (host / 'accepted.tsv').write_text(event_id + '\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t2026-01-01T00:00:04Z\n')
            (host / 'samples.jsonl').write_text(json.dumps({'at': '2026-01-01T00:00:00Z', 'process': {},
                'queue': {'delivered': 0}, 'forwardedEvents': {'records': 1}, 'windowsEventLog': []}) + '\n')
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            windows = [{'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T00:01:00Z'}]
            output = Path(directory) / 'result.json'
            argv = ['reconcile.py', '--lab-dir', str(lab), '--start', str(start), '--end', str(start + 60),
                    '--collector', 'Wec=collector', '--out', str(output)]
            with mock.patch('sys.argv', argv), mock.patch.object(reconcile, 'Verifier'), \
                    mock.patch.object(reconcile, 'native', return_value=({event_id}, windows)), \
                    mock.patch.object(reconcile, 'sentinel', return_value=({event_id: {'Copies': 1}}, [],
                        {'p99': 1, 'count': 1, 'negativeSamples': 0}, [])), redirect_stdout(io.StringIO()):
                reconcile.main()
            collector = json.loads(output.read_text())['collectors']['Wec']
            self.assertEqual('invalid', collector['captureEvidence']['sampling']['state'])
            self.assertEqual(1, collector['captureEvidence']['sampling']['invalidSamples'])
            self.assertEqual('unknown', collector['resources']['hours'][0]['coverage'])
            self.assertIn('samples-invalid', collector['exactQualificationProblems'])
            self.assertFalse(collector['exact'])

    def test_partial_sample_cli_preserves_valid_hour_without_qualifying_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / 'lab'
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            event_id = 'winevt-' + 'a' * 32
            (host / 'accepted.tsv').write_text(event_id + '\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t2026-01-01T00:00:04Z\n')
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            def sample(offset):
                return {'at': reconcile.iso(start + offset), 'process': {'pid': 1, 'cpuSeconds': offset,
                        'startedAt': '2025-12-31T23:59:00Z'}, 'queue': {'delivered': 0},
                        'forwardedEvents': {'records': 1}, 'windowsEventLog': []}
            contents = [sample(60), sample(120), {'at': reconcile.iso(start + 3660), 'process': {}}]
            (host / 'samples.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in contents))
            windows = [{'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T02:00:00Z'}]
            output = root / 'result.json'
            argv = ['reconcile.py', '--lab-dir', str(lab), '--start', str(start), '--end', str(start + 7200),
                    '--collector', 'Wec=collector', '--out', str(output)]
            with mock.patch('sys.argv', argv), mock.patch.object(reconcile, 'Verifier'), \
                    mock.patch.object(reconcile, 'native', return_value=({event_id}, windows)), \
                    mock.patch.object(reconcile, 'sentinel', return_value=({event_id: {'Copies': 1}}, [],
                        {'p99': 1, 'count': 1, 'negativeSamples': 0}, [])), redirect_stdout(io.StringIO()):
                reconcile.main()
            collector = json.loads(output.read_text())['collectors']['Wec']
            sampling = collector['captureEvidence']['sampling']
            self.assertEqual(('partial', 2, 1), (sampling['state'], sampling['samples'], sampling['invalidSamples']))
            hours = collector['resources']['hours']
            self.assertEqual(['observed', 'unknown'], [hour['coverage'] for hour in hours])
            self.assertIsNotNone(hours[0]['cpuSecondsPerHour'])
            self.assertIsNone(hours[1]['cpuSecondsPerHour'])
            self.assertFalse(collector['exact'])
            self.assertIsNone(collector['latencyPassesPilotLimit'])

    def test_failed_reconciliation_invalidates_an_old_qualifying_report(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            (host / 'accepted.tsv').write_text('winevt-invalid\t2026-01-01T00:00:10Z\n')
            output = Path(directory) / 'result.json'
            output.write_text('{"exact": true}\n')
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            windows = [{'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T00:01:00Z'}]
            argv = ['reconcile.py', '--lab-dir', str(lab), '--start', str(start), '--end', str(start + 60),
                    '--collector', 'Wec=collector', '--out', str(output)]
            with mock.patch('sys.argv', argv), mock.patch.object(reconcile, 'Verifier'), \
                    mock.patch.object(reconcile, 'native', return_value=(set(), windows)), \
                    self.assertRaises(ValueError):
                reconcile.main()
            self.assertEqual({'status': 'invalid', 'reason': 'reconciliation-not-completed'},
                             json.loads(output.read_text()))
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            self.assertEqual([], list(Path(directory).glob('.result.json.*.tmp')))

    def test_invalid_argument_invalidates_the_unique_output_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            output = Path(directory) / 'result.json'
            for output_args in (['--out', str(output)], ['--out=' + str(output)]):
                with self.subTest(output_args=output_args):
                    output.write_text('{"exact": true}\n')
                    argv = ['reconcile.py', '--lab-dir', str(lab), '--start', 'not-an-integer', '--end', '60',
                            '--collector', 'Wec=collector', *output_args]
                    with mock.patch('sys.argv', argv), redirect_stdout(io.StringIO()), \
                            mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as raised:
                        reconcile.main()
                    self.assertNotEqual(0, raised.exception.code)
                    self.assertEqual({'status': 'invalid', 'reason': 'reconciliation-not-completed'},
                                     json.loads(output.read_text()))

    def test_output_cannot_replace_lab_input_or_symlink_or_hardlink_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / 'lab'
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            accepted = host / 'accepted.tsv'
            original = b'original laboratory input\n'
            accepted.write_bytes(original)
            symlink = root / 'output-symlink'
            symlink.symlink_to(accepted)
            hardlink = root / 'output-hardlink'
            os.link(accepted, hardlink)
            for output in (accepted, symlink, hardlink):
                with self.subTest(output=output):
                    argv = ['reconcile.py', '--lab-dir', str(lab), '--start', 'not-an-integer',
                            '--end', '60', '--collector', 'Wec=collector', '--out', str(output)]
                    with mock.patch('sys.argv', argv), mock.patch('sys.stderr', new_callable=io.StringIO), \
                            self.assertRaises(SystemExit) as raised:
                        reconcile.main()
                    self.assertNotEqual(0, raised.exception.code)
                    self.assertEqual(original, accepted.read_bytes())
                    self.assertEqual(original, output.read_bytes())

    def test_lab_symlink_to_existing_or_future_output_is_not_mutated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / 'lab'
            lab.mkdir()
            for exists in (True, False):
                with self.subTest(exists=exists):
                    output = root / ('existing.json' if exists else 'future.json')
                    if exists:
                        output.write_text('{"status":"complete"}')
                    alias = lab / 'input-alias'
                    alias.symlink_to(output)
                    argv = ['reconcile.py', '--lab-dir', str(lab), '--start', 'bad', '--end', '60',
                            '--collector', 'Wec=collector', '--out', str(output)]
                    with mock.patch('sys.argv', argv), mock.patch('sys.stderr', new_callable=io.StringIO), \
                            self.assertRaises(SystemExit) as raised:
                        reconcile.main()
                    self.assertNotEqual(0, raised.exception.code)
                    self.assertTrue(alias.is_symlink())
                    if exists:
                        self.assertEqual('{"status":"complete"}', output.read_text())
                    else:
                        self.assertFalse(output.exists())
                    alias.unlink()

    def test_missing_or_ambiguous_lab_does_not_invalidate_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / 'lab'
            lab.mkdir()
            output = root / 'result.json'
            for lab_args in ([], ['--lab-dir', str(lab), '--lab-dir', str(lab)],
                             ['--lab-dir', str(root / 'missing')]):
                with self.subTest(lab_args=lab_args):
                    output.write_text('{"status":"complete"}')
                    argv = ['reconcile.py', *lab_args, '--start', 'bad', '--end', '60',
                            '--collector', 'Wec=collector', '--out', str(output)]
                    with mock.patch('sys.argv', argv), mock.patch('sys.stderr', new_callable=io.StringIO), \
                            self.assertRaises(SystemExit) as raised:
                        reconcile.main()
                    self.assertNotEqual(0, raised.exception.code)
                    self.assertEqual('{"status":"complete"}', output.read_text())

    def test_uninspectable_tree_or_directory_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab, outside, output = root / 'lab', root / 'outside', root / 'result.json'
            lab.mkdir()
            outside.mkdir()
            output.write_text('{"status":"complete"}')
            (lab / 'linked-directory').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                reconcile.verify_disjoint_report(lab, output)
            self.assertEqual('{"status":"complete"}', output.read_text())
            (lab / 'linked-directory').unlink()
            with mock.patch.object(reconcile.os, 'walk', side_effect=OSError('unreadable')):
                with self.assertRaises(ValueError):
                    reconcile.verify_disjoint_report(lab, output)
            self.assertEqual('{"status":"complete"}', output.read_text())

    def test_ambiguous_outputs_fail_without_modifying_either_report(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            one, two = Path(directory) / 'one.json', Path(directory) / 'two.json'
            for path in (one, two):
                path.write_text('{"exact": true}\n')
            argv = ['reconcile.py', '--lab-dir', str(lab), '--start', '0', '--end', '60',
                    '--collector', 'Wec=collector', '--out', str(one), '--out', str(two)]
            with mock.patch('sys.argv', argv), mock.patch('sys.stderr', new_callable=io.StringIO), \
                    self.assertRaises(SystemExit) as raised:
                reconcile.main()
            self.assertNotEqual(0, raised.exception.code)
            self.assertTrue(json.loads(one.read_text())['exact'])
            self.assertTrue(json.loads(two.read_text())['exact'])

    def test_help_does_not_invalidate_a_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'result.json'
            output.write_text('{"status": "complete"}\n')
            with mock.patch('sys.argv', ['reconcile.py', '--out', str(output), '--help']), \
                    redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
                reconcile.main()
            self.assertEqual(0, raised.exception.code)
            self.assertEqual('complete', json.loads(output.read_text())['status'])
    def test_matching_available_sets_do_not_qualify_without_continuity_and_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            event_id = 'winevt-' + 'a' * 32
            (host / 'accepted.tsv').write_text(
                event_id + '\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t2026-01-01T00:00:04Z\n')
            (host / 'samples.jsonl').write_text('')
            (host / 'errors.log').write_text('2026-01-01T00:01:00Z union exit 1\n')
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            windows = [{'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T00:01:00Z'}]
            output = Path(directory) / 'result.json'
            argv = ['reconcile.py', '--lab-dir', str(lab), '--start', str(start), '--end', str(start + 60),
                    '--collector', 'Wec=collector', '--out', str(output)]
            with mock.patch('sys.argv', argv), mock.patch.object(reconcile, 'Verifier'), \
                    mock.patch.object(reconcile, 'native', return_value=({event_id}, windows)), \
                    mock.patch.object(reconcile, 'sentinel', return_value=({event_id: {'Copies': 1}}, [],
                        {'p99': 1, 'count': 1, 'negativeSamples': 0}, [])), redirect_stdout(io.StringIO()):
                reconcile.main()
            collector = json.loads(output.read_text())['collectors']['Wec']
            self.assertTrue(collector['availableObservedSetsEqual'])
            self.assertFalse(collector['exact'])
            self.assertTrue(collector['observedSampleP99WithinLimit'])
            self.assertIsNone(collector['latencyPassesPilotLimit'])
            self.assertIn('destination-completeness-unproven', collector['latencyQualificationProblems'])
            self.assertIn('native-channel-continuity-unproven', collector['exactQualificationProblems'])
            self.assertIn('accepted-capture-coverage-unproven', collector['exactQualificationProblems'])
            self.assertIn('union-failures-observed', collector['exactQualificationProblems'])
            self.assertIn('samples-empty', collector['exactQualificationProblems'])
            self.assertEqual('missing', collector['captureEvidence']['union']['state'])
            self.assertTrue(collector['captureEvidence']['errors']['unionFailuresObserved'])

    def test_cpu_rate_fails_closed_for_restarts_resets_missing_identity_and_bad_time(self):
        first = {'at': '2026-01-01T00:00:00Z',
                 'process': {'pid': 1, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': 10},
                 'eventLogService': {'pid': 2, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': 20}}
        second = {'at': '2026-01-01T00:01:00Z',
                  'process': {'pid': 1, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': 11},
                  'eventLogService': {'pid': 2, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': 22}}
        self.assertEqual(60, reconcile.counter_rate([first, second], 'process', 'cpuSeconds'))
        self.assertEqual(120, reconcile.counter_rate([first, second], 'eventLogService', 'cpuSeconds'))
        for changed in ({'pid': 3}, {'startedAt': '2025-12-31T23:59:01Z'}, {'cpuSeconds': 19}, {'pid': None}):
            with self.subTest(changed=changed):
                broken = {**second, 'eventLogService': {**second['eventLogService'], **changed}}
                self.assertIsNone(reconcile.counter_rate([first, broken], 'eventLogService', 'cpuSeconds'))
        restarted = {**second, 'process': {**second['process'], 'startedAt': '2026-01-01T00:00:30Z'}}
        self.assertIsNone(reconcile.counter_rate([first, restarted], 'process', 'cpuSeconds'))
        self.assertIsNone(reconcile.counter_rate([second, first], 'process', 'cpuSeconds'))

    def test_negative_or_invalid_latency_cannot_pass_pilot_gate(self):
        passing = reconcile.quantiles([1.0, 2.0])
        self.assertEqual((True, []), reconcile.latency_qualification(passing))
        skewed = reconcile.quantiles([-3.0, 1.0])
        self.assertEqual((None, ['negative-latency-clock-skew']), reconcile.latency_qualification(skewed))
        self.assertEqual((None, ['latency-evidence-unavailable']), reconcile.latency_qualification(reconcile.quantiles([])))
        self.assertEqual((None, ['latency-evidence-unavailable']),
                         reconcile.latency_qualification({'p99': float('nan'), 'negativeSamples': 0, 'count': 1}))

    def test_sentinel_event_generated_after_ingestion_is_indeterminate(self):
        class FakeVerifier:
            def query(self, _text):
                return ([{'EventId': 'winevt-' + 'a' * 32, 'Copies': 1,
                          'Generated': '2026-01-01T00:00:30Z',
                          'FirstIngested': '2026-01-01T00:00:10Z'}], 'query-hash')
        start = reconcile.qf.stamp('2026-01-01T00:00:00Z')
        _, _, latency, _ = reconcile.sentinel(FakeVerifier(), 'collector', start, start + 60)
        self.assertEqual(1, latency['negativeSamples'])
        self.assertEqual((None, ['negative-latency-clock-skew']), reconcile.latency_qualification(latency))
    def test_native_export_checks_capture_times_counts_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            dc = lab / 'results' / 'dc'
            dc.mkdir(parents=True)
            report = dc / 'w1.json'
            event_id = 'winevt-' + 'a' * 32
            report_ids = Path(str(report) + '.ids')
            report_ids.write_text(f'{event_id}\t1\t1\t{event_id}\n', encoding='utf-8')
            meta = {'kind': 'native', 'channel': 'Security', 'since': '2026-01-01T00:00:00Z',
                    'until': '2026-01-01T00:01:00Z', 'captureStartedAt': '2026-01-01T00:01:00Z',
                    'capturedAt': '2026-01-01T00:02:00Z', 'examined': 1, 'selected': 1,
                    'unselected': 0, 'distinct': 1, 'duplicateIdentities': 0, 'redactionChangedIds': 0,
                    'identitySetSha256': reconcile.digest({event_id})}
            start = reconcile.qf.stamp(meta['since'])
            end = reconcile.qf.stamp(meta['until'])

            def check(metadata, complete, problem=None):
                report.write_text(json.dumps(metadata), encoding='utf-8')
                _, windows = reconcile.native(lab, start, end)
                self.assertEqual(complete, reconcile.native_window_complete(windows, start, end))
                if problem:
                    self.assertIn(problem, windows[0]['problems'])

            check(meta, True)
            check({**meta, 'captureStartedAt': '2026-01-01T00:00:59Z'}, False,
                  'native-captured-before-window-completed')
            check({key: value for key, value in meta.items() if key != 'captureStartedAt'}, False,
                  'native-capture-time-unproven')
            check({**meta, 'capturedAt': '2026-01-01T00:00:59Z'}, False,
                  'native-captured-before-window-completed')
            check({**meta, 'selected': 2}, False, 'native-counts-mismatch')
            check({**meta, 'examined': 0}, False, 'native-examination-counts-invalid')
            check({**meta, 'identitySetSha256': '0' * 64}, False, 'native-digest-mismatch')
            changed_id = 'winevt-' + 'b' * 32
            report_ids.write_text(f'{changed_id}\t1\t1\t{event_id}\n', encoding='utf-8')
            check({**meta, 'redactionChangedIds': 1, 'identitySetSha256': reconcile.digest({changed_id})},
                  False, 'native-identities-changed-or-duplicated')

    def test_native_invalid_identity_row_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            dc = lab / 'results' / 'dc'
            dc.mkdir(parents=True)
            report = dc / 'w1.json'
            report.write_text(json.dumps({'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T00:01:00Z'}))
            Path(str(report) + '.ids').write_text('bad\t1\t1\twinevt-invalid\n')
            start = reconcile.qf.stamp('2026-01-01T00:00:00Z')
            with self.assertRaises(ValueError):
                reconcile.native(lab, start, start + 60)

    def test_cli_does_not_pass_extra_accepted_event_absent_from_sentinel(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            (host / 'accepted.tsv').write_text(
                'winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t2026-01-01T00:00:04Z\n'
                'winevt-cccccccccccccccccccccccccccccccc\t2026-01-01T00:00:10Z\t2026-01-01T00:00:06Z\t2026-01-01T00:00:05Z\n', encoding='utf-8')
            (host / 'samples.jsonl').write_text('', encoding='utf-8')
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            end = start + 60
            windows = [{'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T00:01:00Z'}]
            destination = {'winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': {'Copies': 1}}
            output = Path(directory) / 'result.json'
            argv = ['reconcile.py', '--lab-dir', str(lab), '--start', str(start), '--end', str(end),
                    '--collector', 'Wec=collector', '--out', str(output)]
            with mock.patch('sys.argv', argv), mock.patch.object(reconcile, 'Verifier'), \
                    mock.patch.object(reconcile, 'native', return_value=({'winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}, windows)), \
                    mock.patch.object(reconcile, 'sentinel', return_value=(destination, [], {'p99': 1}, [])), \
                    redirect_stdout(io.StringIO()):
                reconcile.main()
            actual = json.loads(output.read_text())['collectors']['Wec']
            self.assertFalse(actual['exact'])
            self.assertEqual(1, actual['extraInAccepted'])
            self.assertEqual(0, actual['accepted']['indeterminateWindow'])

    def test_cli_does_not_pass_empty_native_queue_and_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            (host / 'accepted.tsv').write_text('', encoding='utf-8')
            (host / 'samples.jsonl').write_text('', encoding='utf-8')
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            windows = [{'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T00:01:00Z'}]
            output = Path(directory) / 'result.json'
            argv = ['reconcile.py', '--lab-dir', str(lab), '--start', str(start), '--end', str(start + 60),
                    '--collector', 'Wec=collector', '--out', str(output)]
            with mock.patch('sys.argv', argv), mock.patch.object(reconcile, 'Verifier'), \
                    mock.patch.object(reconcile, 'native', return_value=(set(), windows)), \
                    mock.patch.object(reconcile, 'sentinel', return_value=({}, [], {'p99': None}, [])), \
                    redirect_stdout(io.StringIO()):
                reconcile.main()
            self.assertFalse(json.loads(output.read_text())['collectors']['Wec']['exact'])

    def test_native_exports_must_cover_the_full_window_without_gaps(self):
        epoch = reconcile.qf.stamp('2026-01-01T00:00:00Z')
        first = {'since': '2026-01-01T00:00:00Z', 'until': '2026-01-01T00:01:00Z'}
        last = {'since': '2026-01-01T00:01:00Z', 'until': '2026-01-01T00:02:00Z'}
        self.assertTrue(reconcile.native_window_complete([last, first], epoch, epoch + 120))
        self.assertFalse(reconcile.native_window_complete([], epoch, epoch + 120))
        self.assertFalse(reconcile.native_window_complete([last], epoch, epoch + 120))
        self.assertFalse(reconcile.native_window_complete([first], epoch, epoch + 120))
        gap = {'since': '2026-01-01T00:01:01Z', 'until': '2026-01-01T00:02:00Z'}
        self.assertFalse(reconcile.native_window_complete([first, gap], epoch, epoch + 120))

    def test_unexpected_accepted_event_in_window_is_not_hidden(self):
        result = reconcile.reconcile_identities({'expected'}, {'expected': 101, 'extra': 105},
                                                {'expected'}, 100, 110)
        self.assertEqual({'expected', 'extra'}, result['accepted'])
        self.assertEqual(set(), result['indeterminate'])
        self.assertFalse(result['exact'])

    def test_unmatched_event_with_no_proven_source_window_is_indeterminate(self):
        for timestamp in (None,):
            with self.subTest(timestamp=timestamp):
                result = reconcile.reconcile_identities({'expected'}, {'expected': 101, 'extra': timestamp},
                                                        {'expected'}, 100, 110)
                self.assertEqual({'extra'}, result['indeterminate'])
                self.assertFalse(result['exact'])

    def test_outside_source_times_are_excluded_and_in_window_times_are_compared(self):
        result = reconcile.reconcile_identities({'expected'}, {'expected': 105, 'earlier': 99, 'later': 110},
                                                {'expected'}, 100, 110)
        self.assertTrue(result['exact'])
        self.assertEqual({'expected'}, result['accepted'])
        self.assertEqual({'earlier', 'later'}, result['outside'])

    def test_missing_time_is_indeterminate_even_for_a_known_identity(self):
        result = reconcile.reconcile_identities({'expected'}, {'expected': None}, {'expected'}, 100, 110)
        self.assertEqual({'expected'}, result['indeterminate'])
        self.assertFalse(result['exact'])

    def test_missing_accepted_or_destination_does_not_pass(self):
        self.assertFalse(reconcile.reconcile_identities({'a'}, {}, {'a'}, 100, 110)['exact'])
        self.assertFalse(reconcile.reconcile_identities({'a'}, {'a': 101}, set(), 100, 110)['exact'])

    def test_queue_export_loads_generated_time_and_keeps_missing_time_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            (host / 'accepted.tsv').write_text(
                'winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t2026-01-01T00:00:04Z\n'
                'winevt-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\n'
                'winevt-cccccccccccccccccccccccccccccccc\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t\n', encoding='utf-8')
            accepted = reconcile.accepted(lab, 'Wec')
            self.assertEqual(reconcile.qf.stamp('2026-01-01T00:00:04Z'), accepted['winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'])
            self.assertIsNone(accepted['winevt-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'])
            self.assertIsNone(accepted['winevt-cccccccccccccccccccccccccccccccc'])

    def test_nonempty_malformed_generated_timestamps_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            for event_id in ('winevt-' + 'a' * 32, 'other-event'):
                for timestamp in ('invalid', '2026-01-01T00:00:00Z\x00'):
                    with self.subTest(event_id=event_id, timestamp=timestamp):
                        (host / 'accepted.tsv').write_text(
                            event_id + '\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t'
                            + timestamp + '\n', encoding='utf-8')
                        with self.assertRaises(ValueError):
                            reconcile.accepted(lab, 'Wec')

    def test_open_ended_native_export_is_recorded_as_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            dc = lab / 'results' / 'dc'
            dc.mkdir(parents=True)
            (dc / 'open.json').write_text(json.dumps({'since': '2026-01-01T00:00:00Z', 'until': None}))
            start = reconcile.qf.stamp('2026-01-01T00:00:00Z')
            ids, windows = reconcile.native(lab, start, start + 60)
            self.assertEqual(set(), ids)
            self.assertIn('native-window-open-ended', windows[0]['problems'])
            self.assertFalse(reconcile.native_window_complete(windows, start, start + 60))

    def test_malformed_or_incomplete_samples_are_not_silently_discarded(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            for content in ('{"process": {"pid": 1}}\nnot-json\n', '[1, 2]\n',
                            '{"error": "sampling-failed"}\n', '{"process": {}, "value": NaN}\n'):
                with self.subTest(content=content):
                    (host / 'samples.jsonl').write_text(content, encoding='utf-8')
                    valid, invalid = reconcile.samples(lab, 'Wec')
                    self.assertEqual([], valid)
                    self.assertGreater(len(invalid), 0)

    def test_lag_uses_newest_record_id_and_treats_wrap_or_missing_data_as_unknown(self):
        timestamp = '2026-01-01T00:00:00Z'
        start = reconcile.qf.stamp(timestamp)
        def sample(newest, bookmark):
            forwarded = {'records': 25, 'newestRecordIdBasis': 'native-receiving-bookmark-v1', 'newestRecordIdState': 'observed'}
            if newest is not None:
                forwarded['newestRecordId'] = newest
            return {'at': timestamp, 'process': {'pid': 1, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': 1},
                    'eventLogService': {'cpuSeconds': 1}, 'forwardedEvents': forwarded,
                    'windowsEventLog': [{'channel': 'ForwardedEvents', 'gaps': 0, 'resets': 0,
                                         'bookmarkRecordId': bookmark}], 'queue': {'delivered': 0}}
        for newest, bookmark, expected in ((1001, 1000, 1), (None, 1000, None), (999, 1000, None), (1001, None, None)):
            with self.subTest(newest=newest, bookmark=bookmark):
                lag = reconcile.resources([sample(newest, bookmark)], start, start + 60)['hours'][0]['readerLagRecords']
                self.assertEqual(expected, lag['max'])
                self.assertEqual(int(expected is not None), lag['knownSamples'])
                self.assertEqual(int(expected is None), lag['unknownSamples'])
        old_sampler = sample(1001, 1000)
        del old_sampler['forwardedEvents']['newestRecordIdBasis']
        self.assertIsNone(reconcile.resources([old_sampler], start, start + 60)['hours'][0]['readerLagRecords']['max'])
        missing_self_check = sample(1001, 1000)
        del missing_self_check['forwardedEvents']['newestRecordIdState']
        self.assertIsNone(reconcile.resources([missing_self_check], start, start + 60)['hours'][0]['readerLagRecords']['max'])
        missing_self_check['forwardedEvents']['newestRecordIdState'] = 'missing-bookmark-with-records'
        self.assertIsNone(reconcile.resources([missing_self_check], start, start + 60)['hours'][0]['readerLagRecords']['max'])

    def test_partial_samples_keep_valid_hours_and_taint_lag_after_invalid_row(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            def row(offset):
                return {'at': reconcile.iso(start + offset), 'error': None,
                        'process': {'pid': 1, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': offset},
                        'queue': {'delivered': 1}, 'forwardedEvents': {'records': 25, 'newestRecordId': 1001,
                                                                     'newestRecordIdBasis': 'native-receiving-bookmark-v1', 'newestRecordIdState': 'observed'},
                        'windowsEventLog': [{'channel': 'ForwardedEvents', 'gaps': 0, 'resets': 0,
                                             'bookmarkRecordId': 1000}]}
            source = [row(60), row(120), row(3660), {'at': reconcile.iso(start + 3690), 'process': {}},
                      row(3720), row(7260), row(7320)]
            (host / 'samples.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in source))
            valid, invalid = reconcile.samples(lab, 'Wec')
            self.assertEqual((6, 1), (len(valid), len(invalid)))
            result = reconcile.resources(valid, start, start + 10800, invalid_samples=invalid)['hours']
            self.assertEqual(['observed', 'unknown', 'observed'], [hour['coverage'] for hour in result])
            self.assertEqual([0, 1, 0], [hour['invalidSamples'] for hour in result])
            self.assertIsNotNone(result[0]['cpuSecondsPerHour'])
            self.assertIsNone(result[1]['cpuSecondsPerHour'])
            self.assertIsNotNone(result[1]['observedCpuSecondsPerHour'])
            self.assertIsNotNone(result[2]['cpuSecondsPerHour'])
            self.assertEqual(1, result[0]['readerLagRecords']['max'])
            self.assertIsNone(result[2]['readerLagRecords']['max'])

            (host / 'samples.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in source) + 'not-json\n')
            valid, invalid = reconcile.samples(lab, 'Wec')
            result = reconcile.resources(valid, start, start + 10800, invalid_samples=invalid)['hours']
            self.assertEqual(['unknown', 'unknown', 'unknown'], [hour['coverage'] for hour in result])
            self.assertEqual([1, 1, 1], [hour['unlocatedInvalidSamples'] for hour in result])
            self.assertIsNotNone(result[0]['observedCpuSecondsPerHour'])
            self.assertTrue(all(hour['readerLagRecords']['max'] is None for hour in result))

    def test_nonmonotonic_sample_time_marks_the_affected_hour_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
            def row(offset):
                return {'at': reconcile.iso(start + offset),
                        'process': {'pid': 1, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': offset},
                        'queue': {'delivered': 0}, 'forwardedEvents': {'records': 1}, 'windowsEventLog': []}
            (host / 'samples.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in
                [row(60), row(120), row(90), row(3660), row(3720)]))
            valid, invalid = reconcile.samples(lab, 'Wec')
            self.assertEqual((4, 1), (len(valid), len(invalid)))
            self.assertEqual('nonmonotonic-sample-time', invalid[0]['reason'])
            hours = reconcile.resources(valid, start, start + 7200, invalid_samples=invalid)['hours']
            self.assertEqual(['unknown', 'observed'], [hour['coverage'] for hour in hours])
            self.assertIsNotNone(hours[1]['cpuSecondsPerHour'])

    def test_lag_is_unknown_after_source_gap_reset_or_restart(self):
        start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
        def row(offset, gaps=0, resets=0, pid=1):
            return {'at': reconcile.iso(start + offset),
                    'process': {'pid': pid, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': offset},
                    'queue': {'delivered': 0}, 'forwardedEvents': {'records': 25, 'newestRecordId': 1001,
                                                                 'newestRecordIdBasis': 'native-receiving-bookmark-v1', 'newestRecordIdState': 'observed'},
                    'windowsEventLog': [{'channel': 'ForwardedEvents', 'gaps': gaps, 'resets': resets,
                                         'bookmarkRecordId': 1000}]}
        for middle in (row(3660, gaps=1), row(3660, resets=1), row(3660, pid=2)):
            with self.subTest(middle=middle):
                hours = reconcile.resources([row(60), middle, row(7260)], start, start + 10800)['hours']
                self.assertEqual(1, hours[0]['readerLagRecords']['max'])
                self.assertIsNone(hours[1]['readerLagRecords']['max'])
                self.assertIsNone(hours[2]['readerLagRecords']['max'])

    def test_lag_is_unknown_from_backward_receiving_or_bookmark_position(self):
        start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
        def row(offset, newest, bookmark, basis='native-receiving-bookmark-v1'):
            return {'at': reconcile.iso(start + offset),
                    'process': {'pid': 1, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': offset},
                    'queue': {'delivered': 0},
                    'forwardedEvents': {'records': 25, 'newestRecordId': newest, 'newestRecordIdBasis': basis, 'newestRecordIdState': 'observed'},
                    'windowsEventLog': [{'channel': 'ForwardedEvents', 'gaps': 0, 'resets': 0,
                                         'bookmarkRecordId': bookmark}]}
        for middle in (row(3660, 1100, 1000), row(3660, 1300, 900), row(3660, 1300, 1400)):
            with self.subTest(middle=middle):
                hours = reconcile.resources([row(60, 1200, 1000), middle, row(7260, 1400, 1100)],
                                            start, start + 10800)['hours']
                self.assertEqual(200, hours[0]['readerLagRecords']['max'])
                self.assertIsNone(hours[1]['readerLagRecords']['max'])
                self.assertIsNone(hours[2]['readerLagRecords']['max'])

        # An unmarked legacy newest ID is not a trustworthy receiving position and
        # must not taint later marked samples merely because its number is lower.
        hours = reconcile.resources([row(60, 1200, 1000), row(3660, 100, 1000, basis=None),
                                     row(7260, 1300, 1000)], start, start + 10800)['hours']
        self.assertEqual([200, None, 300], [hour['readerLagRecords']['max'] for hour in hours])
        # The next marked sample is still compared to the last marked one, even if
        # a legacy/missing newest ID was observed in between.
        hours = reconcile.resources([row(60, 1200, 1000), row(3660, 100, 1000, basis=None),
                                     row(7260, 1150, 1000)], start, start + 10800)['hours']
        self.assertEqual([200, None, None], [hour['readerLagRecords']['max'] for hour in hours])

    def test_channel_becoming_empty_taints_lag_even_after_regrowth(self):
        start = int(reconcile.qf.stamp('2026-01-01T00:00:00Z'))
        def row(offset, records, newest, bookmark, omit_counters=False):
            status = {'channel': 'ForwardedEvents', 'bookmarkRecordId': bookmark}
            if not omit_counters:
                status.update({'gaps': 0, 'resets': 0})
            return {'at': reconcile.iso(start + offset),
                    'process': {'pid': 1, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': offset},
                    'queue': {'delivered': 0},
                    'forwardedEvents': {'records': records, 'newestRecordId': newest,
                                        'newestRecordIdBasis': 'native-receiving-bookmark-v1',
                                        'newestRecordIdState': 'observed' if newest is not None else 'unknown'},
                    'windowsEventLog': [status]}
        for omit in (False, True):
            with self.subTest(omit_counters=omit):
                hours = reconcile.resources([row(60, 20, 1200, 1000), row(3660, 0, None, None, omit),
                                             row(7260, 50, 1300, 1100)], start, start + 10800)['hours']
                self.assertEqual([200, None, None], [hour['readerLagRecords']['max'] for hour in hours])
                self.assertEqual([1, 0, 0], [hour['readerLagRecords']['knownSamples'] for hour in hours])
        # A channel observed empty before it first contains records is not itself a clear.
        hours = reconcile.resources([row(60, 0, None, None), row(3660, 20, 1200, 1000)],
                                    start, start + 7200)['hours']
        self.assertEqual([None, 200], [hour['readerLagRecords']['max'] for hour in hours])

    def test_out_of_range_or_boolean_positions_are_unknown(self):
        for value in (True, -1, 9223372036854775808, '1', None):
            with self.subTest(value=value):
                self.assertIsNone(reconcile.record_position(value))

    def test_lag_is_unknown_for_missing_gap_state_or_ambiguous_channel(self):
        timestamp = '2026-01-01T00:00:00Z'
        start = reconcile.qf.stamp(timestamp)
        status = {'channel': 'ForwardedEvents', 'gaps': 0, 'resets': 0, 'bookmarkRecordId': 1000}
        base = {'at': timestamp, 'process': {'pid': 1, 'startedAt': '2025-12-31T23:59:00Z', 'cpuSeconds': 1},
                'queue': {'delivered': 0}, 'forwardedEvents': {'records': 25, 'newestRecordId': 1001,
                                                             'newestRecordIdBasis': 'native-receiving-bookmark-v1', 'newestRecordIdState': 'observed'}}
        for windows in ([{key: value for key, value in status.items() if key != 'gaps'}],
                        [status, status], [{'channel': 'Security', 'gaps': 0, 'resets': 0, 'bookmarkRecordId': 1000}]):
            with self.subTest(windows=windows):
                lag = reconcile.resources([{**base, 'windowsEventLog': windows}], start, start + 60)['hours'][0]['readerLagRecords']
                self.assertIsNone(lag['max'])
                self.assertEqual(1, lag['unknownSamples'])

    def test_conflicting_timestamps_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            (host / 'accepted.tsv').write_text(
                'winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t2026-01-01T00:00:10Z\t2026-01-01T00:00:05Z\t2026-01-01T00:00:04Z\n'
                'winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t2026-01-01T00:00:10Z\t2026-01-01T00:00:06Z\t2026-01-01T00:00:05Z\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                reconcile.accepted(lab, 'Wec')

    def test_malformed_windows_ids_and_extra_tsv_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab'
            lab.mkdir()
            host = lab / 'results' / 'Wec'
            host.mkdir(parents=True)
            for row in ('winevt-invalid\t2026-01-01T00:00:00Z\n',
                        'winevt-' + 'a' * 32 + '\tone\ttwo\tthree\tfour\n',
                        'other\u0085id\t2026-01-01T00:00:00Z\n',
                        'other\u2028winevt-' + 'a' * 32 + '\t2026-01-01T00:00:00Z\n',
                        'other\u2029winevt-' + 'a' * 32 + '\t2026-01-01T00:00:00Z\n',
                        'other\rwinevt-' + 'a' * 32 + '\t2026-01-01T00:00:00Z\n'):
                with self.subTest(row=row):
                    (host / 'accepted.tsv').write_text(row, encoding='utf-8')
                    with self.assertRaises(ValueError):
                        reconcile.accepted(lab, 'Wec')

    def test_native_tsv_rejects_unicode_line_and_paragraph_separators(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.ids'
            for separator in ('\u2028', '\u2029'):
                with self.subTest(separator=separator):
                    path.write_text('part' + separator + 'winevt-' + 'a' * 32 + '\t1\t1\t'
                                    + 'winevt-' + 'a' * 32 + '\n', encoding='utf-8')
                    with self.assertRaises(ValueError):
                        list(reconcile.tsv_lines(path))

    def test_tsv_reader_accepts_lf_and_crlf_without_extra_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'identities.tsv'
            path.write_bytes(b'first\t1\r\nsecond\t2\n')
            self.assertEqual(['first\t1', 'second\t2'], list(reconcile.tsv_lines(path)))

    def test_tsv_reader_rejects_bare_cr_between_rows_and_at_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'identities.tsv'
            for content in (b'first\t1\rsecond\t2\n', b'first\t1\r'):
                with self.subTest(content=content):
                    path.write_bytes(content)
                    with self.assertRaises(ValueError):
                        list(reconcile.tsv_lines(path))


if __name__ == '__main__':
    unittest.main()
