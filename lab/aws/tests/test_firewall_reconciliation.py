import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('query_firewall', ROOT / 'monitoring/query-firewall.py')
query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query)
exporter = types.ModuleType('queue_exporter')
source = (ROOT / 'monitoring/export-firewall-queue.sh').read_text().split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
exec(compile(source, 'export-firewall-queue.sh', 'exec'), exporter.__dict__)


class FirewallReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.start = 2000000000
        self.plan = {'schemaVersion': 1, 'runId': 'bower-ws6-20330518-000000', 'collectorId': 'bower-ws6-20330518-000000-linux',
                     'scenario': 'a-steady', 'listener': 'a13', 'startEpoch': self.start, 'collectNotBeforeEpoch': self.start + 60,
                     'expectedBlocks': ['nft:A:0:10'], 'sourceSha256': {'syslog-host.py': 'b' * 64},
                     'generations': [{'kind': 'nft', 'track': 'A', 'first': 0, 'count': 10, 'rate': 10,
                                      'label': 'steady', 'startEpoch': self.start}]}
        self.ids = sorted(query.expected(self.plan))
        self.native = [{'generator': 'nft', 'track': 'A', 'first': 0, 'count': 10, 'sent': 10, 'rate': 10, 'actualRate': 10,
                        'startedAt': query.iso(self.start), 'endedAt': query.iso(self.start + 1), 'nativeCounterDelta': {'A': 10, 'B': 0}}]
        self.queue = {'schemaVersion': 1, 'runId': self.plan['runId'], 'collectorId': self.plan['collectorId'],
                      'scenario': 'a-steady', 'planSha256': 'a' * 64, 'packSha256': 'c' * 64, 'helperSha256': 'b' * 64,
                      'startEpoch': self.start - 2, 'endEpoch': self.start + 60, 'malformedRows': 0,
                      'rows': [{'eventId': value, 'generatedAt': query.iso(self.start), 'receivedAt': query.iso(self.start + 3)} for value in self.ids]}
        self.data = {'tables': [{'columns': [{'name': name} for name in query.COLUMNS],
                                'rows': [[value, 1, query.iso(self.start), query.iso(self.start), query.iso(self.start + 5), query.iso(self.start + 5)] for value in self.ids]}]}

    def report(self):
        return query.reconcile(self.plan, 'a' * 64, 'c' * 64, self.queue, self.native, self.data, self.start + 120)

    def test_verifier_rejects_ids_outside_installed_track_a_rule(self):
        self.plan['expectedBlocks'] = ['nft:A:1999999:1']
        self.assertEqual({'a13-n4449x59999'}, query.expected(self.plan))
        for block in ('nft:A:2000000:1', 'nft:A:1999999:2', 'nft:A:10000000:600'):
            with self.subTest(block=block), self.assertRaises(ValueError):
                query.expected(dict(self.plan, expectedBlocks=[block]))

    def test_dotnet_timestamp_is_normalized_for_python39(self):
        original = query.dt.datetime
        seen = []
        class Python39DateTime:
            @staticmethod
            def fromisoformat(value):
                seen.append(value)
                fraction = value.split('.')[1].split('+')[0] if '.' in value else ''
                if fraction and len(fraction) not in (3, 6):
                    raise ValueError('Python 3.9 rejects unsupported fractional precision')
                return original.fromisoformat(value)
        for parser in (query.stamp, exporter.stamp):
            with mock.patch.object(query.dt, 'datetime', Python39DateTime):
                actual = parser('2026-11-01T01:54:43.7259798+00:00')
                one_digit = parser('2026-11-01T01:54:43.7Z')
            self.assertEqual(original.fromisoformat('2026-11-01T01:54:43.725979+00:00').timestamp(), actual)
            self.assertEqual(original.fromisoformat('2026-11-01T01:54:43.700000+00:00').timestamp(), one_digit)
            for invalid in ('2026-11-01T01:54:43.72597980+00:00', '2026-11-01T01:54:43',
                            '2026-11-01 01:54:43+00:00', 123, None):
                with self.subTest(parser=parser, invalid=invalid), self.assertRaises(ValueError):
                    parser(invalid)
        self.assertTrue(all('.7259798' not in value for value in seen))

    def test_complete_exact_sets(self):
        report = self.report()
        self.assertTrue(report['strictPass'])
        self.assertTrue(report['destinationQueryVerified'])
        self.assertEqual(report['expectedSetSha256'], report['sentinel']['identitySetSha256'])
        self.assertEqual(report['expectedSetSha256'], report['queue']['identitySetSha256'])
        self.assertEqual(query.iso(self.start + 5), report['sentinel']['firstIngested'])

    def test_missing_queue_and_sentinel_are_not_qualified(self):
        self.queue['rows'].pop()
        self.data['tables'][0]['rows'].pop(0)
        report = self.report()
        self.assertFalse(report['strictPass'])
        self.assertFalse(report['destinationQueryVerified'])
        self.assertEqual(1, report['queue']['missing'])
        self.assertEqual(1, report['sentinel']['missing'])
        self.assertEqual(1, report['queueMissingAtSentinel'])

    def test_duplicate_destination_is_counted_and_fails_strict_pass(self):
        self.data['tables'][0]['rows'][0][1] = 3
        report = self.report()
        self.assertTrue(report['identityComplete'])
        self.assertFalse(report['strictPass'])
        self.assertEqual(2, report['sentinel']['duplicateRows'])

    def test_extra_identity_is_counted(self):
        row = self.data['tables'][0]['rows'][0].copy()
        row[0] = 'a13-n4400x39999'
        self.data['tables'][0]['rows'].append(row)
        self.assertEqual(1, self.report()['sentinel']['extra'])
        self.assertFalse(self.report()['identityComplete'])

    def test_stale_queue_cannot_mask_missing_current_attempt(self):
        for field in ('generatedAt', 'receivedAt'):
            with self.subTest(field=field):
                old = self.queue['rows'][0][field]
                self.queue['rows'][0][field] = query.iso(self.start - 600)
                with self.assertRaises(ValueError):
                    self.report()
                self.queue['rows'][0][field] = old

    def test_queue_wrong_scope_or_artifacts_fail(self):
        for field in ('runId', 'collectorId', 'scenario', 'planSha256', 'packSha256', 'helperSha256', 'startEpoch', 'endEpoch', 'malformedRows'):
            with self.subTest(field=field):
                original = self.queue[field]
                self.queue[field] = 'wrong'
                with self.assertRaises(ValueError):
                    self.report()
                self.queue[field] = original

    def test_source_mismatch_and_underload_fail(self):
        for field, value in [('count', 11), ('sent', 9), ('actualRate', 8), ('nativeCounterDelta', {'A': 9, 'B': 0}), ('startedAt', query.iso(self.start + 20))]:
            with self.subTest(field=field):
                old = self.native[0][field]
                self.native[0][field] = value
                with self.assertRaises(ValueError):
                    self.report()
                self.native[0][field] = old

    def test_duplicate_native_report_and_overlapping_blocks_fail(self):
        with self.assertRaises(ValueError):
            query.native_summary(self.plan, self.native * 2)
        self.plan['expectedBlocks'].append('nft:A:5:10')
        with self.assertRaises(ValueError):
            query.expected(self.plan)

    def test_partial_paginated_and_truncated_fail(self):
        for key in ('error', 'partialError', '@odata.nextLink', 'continuationToken', 'truncated'):
            with self.subTest(key=key):
                bad = copy.deepcopy(self.data)
                bad['tables'][0][key] = 'present'
                with self.assertRaises(ValueError):
                    query.sentinel_rows(bad, self.start - 2, self.start + 60, self.start + 120)

    def test_malformed_query_rows_fail(self):
        for column, value in [(0, 'arbitrary payload'), (1, 0), (1, True), (2, query.iso(self.start - 60)), (5, query.iso(self.start + 600))]:
            bad = copy.deepcopy(self.data)
            bad['tables'][0]['rows'][0][column] = value
            with self.subTest(column=column, value=value), self.assertRaises(ValueError):
                query.sentinel_rows(bad, self.start - 2, self.start + 60, self.start + 120)

    def test_query_overflow_and_repeated_aggregate_fail(self):
        with mock.patch.object(query, 'MAX_ROWS', 2), self.assertRaises(ValueError):
            self.report()
        self.data['tables'][0]['rows'].append(self.data['tables'][0]['rows'][0])
        with self.assertRaises(ValueError):
            self.report()

    def test_query_is_exact_run_and_time_scoped_and_bounded(self):
        text = query.query_text(self.plan, self.start + 120)
        for value in (self.plan['collectorId'], 'ApplicationEnvironment == "validation"', 'take 200001', query.iso(self.start - 2), query.iso(self.start + 60)):
            self.assertIn(value, text)
        self.assertNotIn('RawEnvelope', text)
        self.plan['collectorId'] = '" | union *'
        with self.assertRaises(ValueError):
            query.query_text(self.plan, self.start + 120)

    def test_export_is_metadata_only_and_keeps_stale_expected(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            database = directory / 'queue.db'
            with sqlite3.connect(database) as connection:
                connection.execute('CREATE TABLE queue_events (event_id TEXT, payload TEXT, received_at TEXT)')
                for identity, generated in [(self.ids[0], self.start - 600), (self.ids[1], self.start), ('a13-n4400x39998', self.start - 600), ('a13-n4400x39999', self.start)]:
                    payload = {'timeGenerated': query.iso(generated), 'collector': {'id': self.plan['collectorId']},
                               'application': {'name': 'nftables-firewall', 'environment': 'validation'},
                               'eventType': 'network_connection_denied', 'secret': 'DO-NOT-EXPORT'}
                    connection.execute('INSERT INTO queue_events VALUES (?, ?, ?)', (identity, json.dumps(payload), query.iso(generated + 2).replace('+00:00', '.1234567+00:00')))
            pack = directory / 'pack'
            pack.write_bytes(b'synthetic pack fixture')
            report = exporter.export(database, self.plan['runId'], 'a-steady', 'a' * 64, 'nft:A:0:10', self.start - 2, self.start + 60, pack, pack)
            self.assertEqual(3, len(report['rows']))
            self.assertEqual({'eventId', 'generatedAt', 'receivedAt'}, set(report['rows'][0]))
            self.assertNotIn('DO-NOT-EXPORT', json.dumps(report))
            self.assertEqual(query.iso(self.start - 600), report['rows'][0]['generatedAt'])

    def test_oversized_input_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_text('{"large":"input"}')
            with self.assertRaises(ValueError):
                query.read_json(path, 4)

    def test_verifier_uses_only_separate_identity_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            certificate = directory / 'verifier-identity.pem'
            certificate.write_text('fixture is not a credential')
            certificate.chmod(0o600)
            state = {'subscription': query.SUBSCRIPTION, 'tenant': query.TENANT, 'group': 'fixture', 'workspaceName': 'fixture',
                     'workspaceId': query.SUBSCRIPTION, 'identities': {'verifier': {'appId': query.TENANT, 'certificatePath': str(certificate)}},
                     'workspaceResourceId': '/subscriptions/' + query.SUBSCRIPTION + '/resourceGroups/fixture/providers/Microsoft.OperationalInsights/workspaces/fixture'}
            (directory / 'azure-state.json').write_text(json.dumps(state))
            _, _, pem, cache = query.verifier_context(directory)
            self.assertEqual(certificate, pem)
            self.assertEqual(directory / 'azure-cli-verifier', cache)
            certificate.chmod(0o644)
            with self.assertRaises(ValueError):
                query.verifier_context(directory)
            certificate.chmod(0o600)
            cache.rmdir()
            cache.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                query.verifier_context(directory)

    def test_live_query_auth_checks_identity_and_handles_empty_account_set(self):
        class Response:
            status = 200
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, bound):
                return json.dumps({'tables': []}).encode()

        directory = Path('/private/fixture')
        state = {'workspaceId': query.SUBSCRIPTION}
        identity = {'appId': query.TENANT}
        results = [[], None, {'tenantId': query.TENANT, 'id': query.SUBSCRIPTION,
                              'user': {'name': query.TENANT, 'type': 'servicePrincipal'}}, {'accessToken': 'synthetic-token'}]
        processes = [types.SimpleNamespace(returncode=0, stdout=json.dumps(value) if value is not None else '') for value in results]
        with mock.patch.object(query, 'verifier_context', return_value=(state, identity, directory / 'verifier-identity.pem', directory / 'azure-cli-verifier')), \
                mock.patch.object(query.subprocess, 'run', side_effect=processes) as cli, \
                mock.patch.object(query.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value = Response()
            data, _, _ = query.query_live(directory, 'scoped query', timespan_seconds=900)
            self.assertEqual({'tables': []}, data)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual({'query': 'scoped query', 'timespan': 'PT900S'}, json.loads(request.data))
            for call in cli.call_args_list:
                self.assertEqual(str(directory / 'azure-cli-verifier'), call.kwargs['env']['AZURE_CONFIG_DIR'])
                self.assertNotIn('synthetic-token', str(call.args))
            self.assertIn('--certificate', cli.call_args_list[0].args[0])
            self.assertNotIn('--password', cli.call_args_list[0].args[0])
            # Historical identity reconciliation must not acquire a recent-only scan window.
            cli.side_effect = processes
            query.query_live(directory, 'explicit historical bounds')
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual({'query': 'explicit historical bounds'}, json.loads(request.data))

    def test_live_query_rejects_unbounded_or_non_integer_window_before_authentication(self):
        with mock.patch.object(query, 'verifier_context') as context:
            for value in (0, -1, 172801, True, 1.5, 'PT15M', float('inf')):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    query.query_live(Path('/private/fixture'), 'query', timespan_seconds=value)
            context.assert_not_called()


    def test_optional_destination_evidence_preserves_only_validated_rows_and_provenance(self):
        self.data['untrustedBody'] = 'synthetic-secret'
        self.data['tables'][0]['untrustedMetadata'] = 'synthetic-secret'
        result = query.destination_evidence(self.plan, 'a' * 64, 'c' * 64, self.data,
                                            self.start + 120, '11111111-1111-1111-1111-111111111111',
                                            '22222222-2222-2222-2222-222222222222')
        self.assertNotIn('synthetic-secret', json.dumps(result))
        self.assertEqual(self.data['tables'][0]['rows'], result['rows'])
        self.assertEqual(query.digest(self.ids), result['identitySetSha256'])
        self.assertEqual(hashlib.sha256(query.query_text(self.plan, self.start + 120).encode()).hexdigest(), result['query']['sha256'])
        self.assertIsNone(result['query']['apiTimespan'])
        self.assertFalse(result['deliveryQualified'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'destination.json'
            receipt = query.write_destination_evidence(path, result)
            self.assertEqual(query.sha(path), receipt['sha256'])
            self.assertEqual(path.stat().st_size, receipt['bytes'])
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                query.write_destination_evidence(path, result)
            oversized = Path(directory) / 'oversized.json'
            with mock.patch.object(query, 'MAX_BYTES', 10), self.assertRaisesRegex(ValueError, 'Oversized'):
                query.write_destination_evidence(oversized, result)
            self.assertFalse(oversized.exists())

    def test_optional_destination_evidence_rejects_unvalidated_payloads(self):
        for mutation in ('payload', 'timestamp', 'partial', 'count'):
            data = copy.deepcopy(self.data)
            if mutation == 'payload':
                data['tables'][0]['rows'][0].append('synthetic-secret')
            elif mutation == 'timestamp':
                data['tables'][0]['rows'][0][4] = 'synthetic-secret'
            elif mutation == 'partial':
                data['partialError'] = {'code': 'PartialQueryFailure'}
            else:
                data['tables'][0]['rows'][0][1] = 9223372036854775808
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                query.destination_evidence(self.plan, 'a' * 64, 'c' * 64, data,
                                           self.start + 120, '11111111-1111-1111-1111-111111111111',
                                           '22222222-2222-2222-2222-222222222222')

    def test_destination_evidence_cli_is_opt_in_and_links_new_private_artifact(self):
        cutoff = self.start + 120
        class Clock(query.dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls.fromtimestamp(cutoff, tz)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path, queue_path, native_path = (root / name for name in ('plan.json', 'queue.json', 'native.json'))
            plan_path.write_text(json.dumps(self.plan))
            queue = dict(self.queue, planSha256=query.sha(plan_path))
            queue_path.write_text(json.dumps(queue))
            native_path.write_text(json.dumps(self.native[0]))
            common = ['query-firewall.py', '--plan', str(plan_path), '--queue', str(queue_path),
                      '--native', str(native_path), '--pack-sha256', 'c' * 64, '--azure-state-dir', str(root)]
            for label, optional, missing in (('default', False, False), ('optional', True, False), ('missing', True, True)):
                report = root / (label + '.json')
                evidence = root / (label + '-destination.json')
                query_data = copy.deepcopy(self.data)
                if missing:
                    query_data['tables'][0]['rows'].pop()
                argv = common + ['--output', str(report)]
                if optional:
                    argv += ['--destination-evidence', str(evidence)]
                with mock.patch.object(query.sys, 'argv', argv), mock.patch.object(query.dt, 'datetime', Clock), \
                        mock.patch.object(query, 'query_live', return_value=(query_data, '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')), \
                        mock.patch('sys.stdout', new=io.StringIO()):
                    self.assertEqual(1 if missing else 0, query.main())
                saved = json.loads(report.read_text())
                self.assertEqual(optional, 'destinationEvidence' in saved)
                self.assertEqual(not missing, saved['strictPass'])
                if optional:
                    self.assertEqual(query.sha(evidence), saved['destinationEvidence']['sha256'])
                    self.assertEqual(9 if missing else 10, json.loads(evidence.read_text())['distinctIdentities'])
                else:
                    self.assertFalse(evidence.exists())
            # Existing output must fail before another authentication/query attempt.
            with mock.patch.object(query.sys, 'argv', argv), mock.patch.object(query, 'query_live') as live, \
                    self.assertRaisesRegex(ValueError, 'distinct new paths'):
                query.main()
            live.assert_not_called()

if __name__ == '__main__':
    unittest.main()


class ScenarioNameTests(unittest.TestCase):
    def test_plans_with_digits_in_scenario_names_are_accepted_and_others_refused(self):
        base = {'schemaVersion': 1, 'runId': 'bower-fw-20330518-000000', 'collectorId': 'bower-fw-20330518-000000-linux',
                'listener': 'a13', 'startEpoch': 2000000000, 'collectNotBeforeEpoch': 2000000905,
                'expectedBlocks': ['nft:A:1940000:10']}
        self.assertEqual(10, len(query.expected(dict(base, scenario='a-destination-outage-15m'))))
        for name in ('a-Outage', 'c-steady', 'a_steady', 'a-steady;x'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                query.expected(dict(base, scenario=name))
