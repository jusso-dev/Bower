import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1] / 'monitoring'
spec = importlib.util.spec_from_file_location('query_wec', ROOT / 'query-wec.py')
query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query)


class WecReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.start = 2000000000
        self.ids = {'winevt-' + format(index, '032x') for index in range(10)}
        self.id_bytes = ('\r\n'.join(sorted(self.ids)) + '\r\n').encode('ascii')
        self.evidence = {'ids': self.ids, 'fileSha256': hashlib.sha256(self.id_bytes).hexdigest()}
        counters = {'id': 'wec-security', 'channel': 'ForwardedEvents', 'state': 'running', 'queued': 0,
                    **{key: 0 for key in ('rejected', 'parserErrors', 'malformed', 'oversized', 'gaps', 'resets', 'cursorConflicts')}}
        summary = {'count': 10, 'unique': 10, 'invalidNetworkLogons': 0, 'idsSha256': self.evidence['fileSha256']}
        self.phase = {'runId': 'bower-ws6-20330518-000000', 'phase': 'steady', 'requestedRate': 10,
                      'startedAt': query.transport.iso(self.start), 'endedAt': query.transport.iso(self.start + 1),
                      'eventWindowEndedAt': query.transport.iso(self.start + 6), 'eventWindowPaddingSeconds': 5,
                      'generator': {'requested': 10, 'scheduled': 10, 'completed': 10, 'unexpectedSuccesses': 0,
                                    'drained': True, 'cancelled': False, 'seconds': 1, 'actualRate': 10,
                                    'maxConcurrency': 2, 'resultCodes': {'1326': 10},
                                    'startedAt': query.transport.iso(self.start), 'endedAt': query.transport.iso(self.start + 1),
                                    'credentialIsolation': 'per-worker-logon-new-credentials', 'initialized': True,
                                    'sessionSetupFailures': 0, 'impersonationFailures': 0, 'revertFailures': 0,
                                    'handleCloseFailures': 0, 'sessionResultCodes': {}, 'initializationFailureReasons': {},
                                    'sessionCleanupFailures': 0, 'sessionCleanupCodes': {'2250': 2}},
                      'native': copy.deepcopy(summary), 'forwarded': copy.deepcopy(summary),
                      'queueIdentities': {'count': 10, 'exactNativeMatch': True, 'idsSha256': self.evidence['fileSha256']},
                      'acceptedDelta': 10, 'sourceBefore': counters, 'sourceAfter': dict(counters, queued=10), 'nativeVerified': True}
        self.phase['native'].update(firstEventAt=query.transport.iso(self.start + .05),
                                    lastEventAt=query.transport.iso(self.start + .95), observedRate=10)
        self.data = {'tables': [{'name': 'PrimaryResult',
                                'columns': [{'name': name, 'type': kind} for name, kind in zip(query.COLUMNS, query.TYPES)],
                                'rows': [[identity, 1, query.transport.iso(self.start + .2), query.transport.iso(self.start + .2),
                                          query.transport.iso(self.start + 1.5), query.transport.iso(self.start + 1.5)]
                                         for identity in sorted(self.ids)]}]}

    def source(self):
        return query.source_evidence(self.phase, self.evidence, self.evidence, self.evidence)

    def report(self):
        return query.reconcile(self.source(), self.data, self.start + 7)

    def test_exact_end_to_end_pass_retains_only_identity_metadata(self):
        report = self.report()
        self.assertTrue(report['strictPass'])
        self.assertTrue(report['destinationQueryVerified'])
        self.assertEqual(report['expectedSetSha256'], report['sentinel']['identitySetSha256'])
        self.assertEqual(query.transport.iso(self.start + 1.5), report['sentinel']['lastIngestedAt'])
        self.assertEqual(query.transport.iso(self.start + .2), report['sentinel']['firstGeneratedAt'])
        self.assertEqual(10, len(report['destinationIdentityRows']))
        self.assertEqual(query.COLUMNS, report['destinationColumns'])

    def test_explicit_stable_phase_credentials_require_complete_owned_cleanup(self):
        self.phase['mode'] = 'phase'
        self.phase['generator'].update(credentialIsolation='per-phase-logon-new-credentials',
            executionKind='native-windows', credentialMode='explicit-stable-per-phase', workerCount=10, activeAtReturn=0,
            workersRemainingAtReturn=0, sessionCleanupCodes={'2250': 1})
        self.phase['generator'].update(warmupRequired=True, warmupVerified=True, warmup={
            'kind': 'native-warmup', 'requested': 100, 'requestedRate': 10, 'scheduled': 100, 'completed': 100,
            'drained': True, 'unexpectedSuccesses': 0, 'resultCodes': {'1326': 100},
            'startedAt': query.transport.iso(self.start - 20), 'endedAt': query.transport.iso(self.start - 10),
            'deadlineAt': query.transport.iso(self.start + 10), 'completedAt': query.transport.iso(self.start - 1),
            'nativeCount': 80, 'forwardedCount': 80, 'queueCount': 80,
            'nativeIdsSha256': 'd' * 64, 'forwardedIdsSha256': 'd' * 64, 'queueIdsSha256': 'd' * 64})
        self.assertTrue(self.report()['strictPass'])
        original = copy.deepcopy(self.phase)
        for key, value in [('executionKind', 'simulated'), ('credentialMode', 'implicit-token'), ('workerCount', 64),
                           ('activeAtReturn', 1), ('workersRemainingAtReturn', 1),
                           ('sessionCleanupCodes', {}), ('sessionCleanupCodes', {'2250': 2}), ('warmupVerified', False), ('warmupRequired', False)]:
            self.phase = copy.deepcopy(original)
            self.phase['generator'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.source()
        for key, value in [('completed', 99), ('resultCodes', {'1219': 100}), ('queueCount', 79),
                           ('completedAt', query.transport.iso(self.start + .1)), ('forwardedIdsSha256', 'e' * 64)]:
            self.phase = copy.deepcopy(original)
            self.phase['generator']['warmup'][key] = value
            with self.subTest(warmup=key), self.assertRaises(ValueError): self.source()
        self.phase = copy.deepcopy(original)
        self.phase['generator'].update(credentialIsolation='per-worker-logon-new-credentials', workerCount=4, sessionCleanupCodes={'2250': 4})
        self.assertTrue(self.report()['strictPass'])
        self.phase['generator']['sessionCleanupCodes'] = {'2250': 3}
        with self.assertRaises(ValueError): self.source()
        self.phase['generator'].update(sessionCleanupCodes={'2250': 4}, credentialMode='implicit-token')
        with self.assertRaises(ValueError): self.source()
        self.phase = copy.deepcopy(original)
        self.phase['mode'] = 'diagnostic'
        with self.assertRaises(ValueError): self.source()

    def test_missing_extra_and_duplicate_rows_fail_independently(self):
        self.data['tables'][0]['rows'].pop()
        extra = self.data['tables'][0]['rows'][0].copy()
        extra[0] = 'winevt-' + 'f' * 32
        self.data['tables'][0]['rows'].append(extra)
        self.data['tables'][0]['rows'][0][1] = 3
        report = self.report()
        self.assertFalse(report['strictPass'])
        self.assertFalse(report['destinationQueryVerified'])
        self.assertEqual((1, 1, 2, 1), tuple(report['sentinel'][key] for key in
                                          ('missing', 'extra', 'duplicateRows', 'duplicateIdentities')))
        self.assertNotEqual(query.digest(set()), report['sentinel']['missingSetSha256'])

    def test_empty_destination_is_complete_query_but_failed_delivery(self):
        self.data['tables'][0]['rows'] = []
        report = self.report()
        self.assertTrue(report['queryResponseComplete'])
        self.assertFalse(report['strictPass'])
        self.assertEqual(10, report['sentinel']['missing'])
        self.assertIsNone(report['sentinel']['firstIngestedAt'])

    def test_source_file_bytes_hash_differs_from_canonical_set_hash(self):
        self.assertNotEqual(self.evidence['fileSha256'], query.digest(self.ids))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ids'
            path.write_bytes(self.id_bytes)
            self.assertEqual(self.evidence, query.read_ids(path))
            path.write_bytes(self.id_bytes.replace(b'\r\n', b'\n'))
            lf = query.read_ids(path)
            self.assertEqual(self.ids, lf['ids'])
            self.assertNotEqual(self.evidence['fileSha256'], lf['fileSha256'])
            with self.assertRaises(ValueError):
                query.source_evidence(self.phase, lf, self.evidence, self.evidence)

    def test_bad_identity_files_rejected(self):
        identity = next(iter(self.ids)).encode()
        invalid = [b'', b'\xef\xbb\xbf' + identity, identity + b'\n' + identity,
                   identity + b'\n\n', identity + b'\r', identity.upper(), identity + b'\t', b'../../secret']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ids'
            for raw in invalid:
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        query.read_ids(path)
            with mock.patch.object(query, 'MAX_ID_BYTES', 4):
                path.write_bytes(identity)
                with self.assertRaises(ValueError):
                    query.read_ids(path)

    def test_queue_exact_identity_is_required_beyond_equal_counts(self):
        replacement = set(self.ids)
        replacement.remove(next(iter(replacement)))
        replacement.add('winevt-' + 'e' * 32)
        with self.assertRaises(ValueError):
            query.source_evidence(self.phase, self.evidence, self.evidence, dict(self.evidence, ids=replacement))

    def test_fixed_audit_window_includes_late_native_creation_without_lowering_rate(self):
        self.phase['native'].update(firstEventAt=query.transport.iso(self.start + 1.05),
                                    lastEventAt=query.transport.iso(self.start + 1.95), observedRate=10)
        for row in self.data['tables'][0]['rows']:
            row[2] = row[3] = query.transport.iso(self.start + 1.5)
            row[4] = row[5] = query.transport.iso(self.start + 2.5)
        report = self.report()
        self.assertTrue(report['strictPass'])
        self.assertEqual(10, report['actualRate'])
        self.assertEqual(10, report['nativeObservedRate'])
        self.assertEqual(query.transport.iso(self.start + 1), report['endedAt'])
        self.assertEqual(query.transport.iso(self.start + 6), report['eventWindowEndedAt'])
        self.assertIn('TimeGenerated < datetime(' + query.transport.iso(self.start + 6) + ')',
                      query.query_text(self.source(), self.start + 7))

    def test_source_hash_counter_and_failure_flags_rejected(self):
        changes = [(['nativeVerified'], False), (['acceptedDelta'], 9),
                   (['queueIdentities', 'exactNativeMatch'], False), (['queueIdentities', 'idsSha256'], '0' * 64),
                   (['native', 'invalidNetworkLogons'], 1), (['forwarded', 'count'], 9),
                   (['sourceAfter', 'queued'], 20), (['sourceAfter', 'gaps'], 1),
                   (['sourceBefore', 'queued'], True), (['sourceAfter', 'state'], 'backpressure'),
                   (['generator', 'cancelled'], True), (['generator', 'drained'], False),
                   (['generator', 'maxConcurrency'], 65), (['generator', 'resultCodes'], {'1219': 10}), (['generator', 'resultCodes'], {'1326': 9}),
                   (['generator', 'initialized'], False), (['generator', 'credentialIsolation'], 'shared'),
                   (['generator', 'impersonationFailures'], 1), (['generator', 'sessionResultCodes'], {'1326': 1}),
                   (['generator', 'sessionCleanupFailures'], 1), (['generator', 'sessionCleanupCodes'], {'5': 1}),
                   (['generator', 'initializationFailureReasons'], {'failed': 1}),
                   (['eventWindowPaddingSeconds'], 6), (['eventWindowEndedAt'], query.transport.iso(self.start + 7)),
                   (['native', 'observedRate'], 9), (['native', 'lastEventAt'], query.transport.iso(self.start + 6)),
                   (['generator', 'unexpectedSuccesses'], 1), (['generator', 'completed'], 9),
                   (['generator', 'actualRate'], 9.8), (['generator', 'seconds'], float('nan')),
                   (['startedAt'], '2033-05-18T00:00:00')]
        original = copy.deepcopy(self.phase)
        for fields, value in changes:
            with self.subTest(fields=fields):
                self.phase = copy.deepcopy(original)
                target = self.phase
                for field in fields[:-1]:
                    target = target[field]
                target[fields[-1]] = value
                with self.assertRaises(ValueError):
                    self.source()

    def test_partial_error_continuation_and_over_limit_responses_rejected(self):
        for key in ('error', 'partialError', '@odata.nextLink', 'continuationToken', 'truncated'):
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data['metadata'] = {key: 'present'}
                with self.assertRaises(ValueError):
                    query.reconcile(self.source(), data, self.start + 7)
        with mock.patch.object(query, 'MAX_ROWS', 9):
            with self.assertRaises(ValueError):
                self.report()

    def test_malformed_query_aggregates_and_timestamps_rejected(self):
        original = copy.deepcopy(self.data)
        for index, value in [(0, 'not-windows'), (1, True), (1, 0), (1, 2 ** 63),
                             (2, query.transport.iso(self.start - 1)), (3, query.transport.iso(self.start + 6)),
                             (4, None), (5, query.transport.iso(self.start + 8))]:
            with self.subTest(index=index, value=value):
                self.data = copy.deepcopy(original)
                self.data['tables'][0]['rows'][0][index] = value
                with self.assertRaises((ValueError, AttributeError, TypeError)):
                    self.report()
        self.data = copy.deepcopy(original)
        self.data['tables'][0]['rows'].append(self.data['tables'][0]['rows'][0])
        with self.assertRaises(ValueError):
            self.report()

    def test_wrong_query_schema_or_precompletion_cutoff_rejected(self):
        self.data['tables'][0]['columns'][1]['type'] = 'string'
        with self.assertRaises(ValueError):
            self.report()
        with self.assertRaises(ValueError):
            query.query_text(self.source(), self.start)

    def test_query_scopes_collector_population_without_hiding_extra_ids(self):
        text = query.query_text(self.source(), self.start + 7)
        self.assertIn('CollectorId == "bower-ws6-20330518-000000-windows"', text)
        self.assertIn('ApplicationName == "windows-security"', text)
        self.assertIn('ApplicationEnvironment == "production"', text)
        self.assertIn('summarize Copies=count()', text)
        self.assertIn('| take 200001', text)
        self.assertNotIn('EventId in', text)
        self.assertNotIn(next(iter(self.ids)), text)

    def test_main_writes_bounded_metadata_report_without_printing_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'phase.json').write_text('\ufeff' + json.dumps(self.phase), encoding='utf-8')
            for name in ('native', 'forwarded', 'queue'):
                (root / name).write_bytes(self.id_bytes)
            output = root / 'verified.json'
            argv = ['--phase', str(root / 'phase.json'), '--native', str(root / 'native'), '--forwarded', str(root / 'forwarded'),
                    '--queue', str(root / 'queue'), '--azure-state-dir', str(root), '--output', str(output)]
            now = query.dt.datetime.fromtimestamp(self.start + 7, query.dt.timezone.utc)
            with mock.patch.object(query.transport, 'query_live', return_value=(self.data, 'workspace', 'verifier')) as live, mock.patch('builtins.print') as printer, mock.patch.object(query.dt, 'datetime', wraps=query.dt.datetime) as clock:
                clock.now.return_value = now
                self.assertEqual(0, query.main(argv))
                live.assert_called_once()
                report = json.loads(output.read_text())
                self.assertEqual(10, len(report['destinationIdentityRows']))
                self.assertNotIn('destinationIdentityRows', json.loads(printer.call_args.args[0]))
                with self.assertRaises(ValueError):
                    query.main(argv)
                live.assert_called_once()

    def test_invalid_native_phase_never_queries_or_writes_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.phase['nativeVerified'] = False
            (root / 'phase.json').write_text(json.dumps(self.phase))
            for name in ('native', 'forwarded', 'queue'):
                (root / name).write_bytes(self.id_bytes)
            output = root / 'verified.json'
            argv = ['--phase', str(root / 'phase.json'), '--native', str(root / 'native'), '--forwarded', str(root / 'forwarded'),
                    '--queue', str(root / 'queue'), '--azure-state-dir', str(root), '--output', str(output)]
            with mock.patch.object(query.transport, 'query_live') as live:
                with self.assertRaises(ValueError):
                    query.main(argv)
                live.assert_not_called()
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
