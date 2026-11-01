import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / 'monitoring/query-wec-outage.py'
spec = importlib.util.spec_from_file_location('wec_outage_query', PATH)
query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query)


class OutageQueryTests(unittest.TestCase):
    def setUp(self):
        self.plan = {'runId': 'bower-ws6-20261101-011000', 'phase': 'outage-01',
                     'kind': 'native-windows-wec-destination-outage', 'status': 'frozen-before-dispatch',
                     'measured': {'rate': 10, 'seconds': 3600, 'expectedNativeCount': 36000}}
        self.start = query.transport.stamp('2026-11-01T03:47:29Z')
        self.cutoff = self.start + 3602
        self.data = {'tables': [{'name': 'PrimaryResult', 'columns': query.COLUMNS, 'rows': [[0, None, None]]}]}

    def test_empty_observation_has_no_delivery_claim(self):
        report = query.summarize(self.data, self.cutoff)
        self.assertTrue(report['noIngestionObservedAtCutoff'])
        self.assertEqual(0, report['rows'])
        text = query.query_text(self.plan, self.start, self.cutoff, self.cutoff)
        self.assertIn('bower-ws6-20261101-011000-windows', text)
        self.assertIn('ApplicationEnvironment == "production"', text)
        self.assertIn('ingestion_time() <= datetime(', text)
        self.assertNotIn('EventId in', text)

    def test_nonempty_observation_retained_as_failure(self):
        self.data['tables'][0]['rows'] = [[2, query.transport.iso(self.start + 1), query.transport.iso(self.start + 2)]]
        self.assertFalse(query.summarize(self.data, self.cutoff)['noIngestionObservedAtCutoff'])

    def test_partial_wrong_schema_and_malformed_counts_fail(self):
        for key in ('error', 'partialError', 'continuationToken', '@odata.nextLink', 'truncated'):
            data = copy.deepcopy(self.data)
            data[key] = 'present'
            with self.subTest(key=key), self.assertRaises(ValueError): query.summarize(data, self.cutoff)
        for row in ([True, None, None], [-1, None, None], [2 ** 63, None, None], [0, '2026-11-01T03:47:29Z', None],
                    [1, None, None], [1, query.transport.iso(self.start), query.transport.iso(self.cutoff + 1)]):
            data = copy.deepcopy(self.data)
            data['tables'][0]['rows'] = [row]
            with self.subTest(row=row), self.assertRaises((ValueError, TypeError)): query.summarize(data, self.cutoff)
        self.data['tables'][0]['columns'] = []
        with self.assertRaises(ValueError): query.summarize(self.data, self.cutoff)

    def test_scope_injection_wrong_pilot_and_future_ranges_fail(self):
        for field, value in [('runId', '" | take 1'), ('phase', '../escape'), ('kind', 'other'), ('status', 'draft')]:
            plan = copy.deepcopy(self.plan)
            plan[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): query.query_text(plan, self.start, self.cutoff, self.cutoff)
        self.plan['measured']['rate'] = 100
        with self.assertRaises(ValueError): query.query_text(self.plan, self.start, self.cutoff, self.cutoff)
        self.plan['measured']['rate'] = 10
        for since, until in [(self.start, self.cutoff + 1), (self.start, self.start), (self.start - 10000, self.cutoff)]:
            with self.assertRaises(ValueError): query.query_text(self.plan, since, until, self.cutoff)

    def test_main_uses_new_private_report_and_never_claims_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / 'plan.json'
            plan.write_text(json.dumps(self.plan))
            output = root / 'observation.json'
            argv = ['--plan', str(plan), '--since', query.transport.iso(self.start), '--azure-state-dir', str(root), '--output', str(output)]
            now = dt.datetime.fromtimestamp(self.cutoff, dt.timezone.utc)
            with mock.patch.object(query.transport, 'query_live', return_value=(self.data, 'workspace', 'verifier')) as live, mock.patch.object(query.dt, 'datetime', wraps=dt.datetime) as clock, mock.patch('builtins.print'):
                clock.now.return_value = now
                self.assertEqual(0, query.main(argv))
                report = json.loads(output.read_text())
                self.assertFalse(report['destinationQueryVerified'])
                self.assertFalse(report['deliveryQualified'])
                self.assertTrue(report['observation']['noIngestionObservedAtCutoff'])
                self.assertEqual(0, output.stat().st_mode & 0o077)
                with self.assertRaises(ValueError): query.main(argv)
                live.assert_called_once()


    def test_changed_plan_during_query_cannot_create_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / 'plan.json'
            plan.write_text(json.dumps(self.plan))
            output = root / 'observation.json'
            def changed(*args, **kwargs):
                plan.write_text('{}')
                return self.data, 'workspace', 'verifier'
            now = dt.datetime.fromtimestamp(self.cutoff, dt.timezone.utc)
            with mock.patch.object(query.transport, 'query_live', side_effect=changed), mock.patch.object(query.dt, 'datetime', wraps=dt.datetime) as clock:
                clock.now.return_value = now
                with self.assertRaises(ValueError):
                    query.main(['--plan', str(plan), '--since', query.transport.iso(self.start), '--azure-state-dir', str(root), '--output', str(output)])
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
