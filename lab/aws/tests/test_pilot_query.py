"""Exact destination reconciliation must reject partial or malformed metadata."""
import datetime as dt
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('query', Path(__file__).parents[1]/'scripts/query-pilot.py')
query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query)


class PilotQueryTests(unittest.TestCase):
    def data(self, identifiers=('b', 'a')):
        columns = ['EventId', 'EventType', 'PolicyHash', 'TimeGenerated', 'Ingested', 'RawPrivacyMatch']
        return {'tables':[{'columns':[{'name':name} for name in columns],
                           'rows':[[identity, 'authentication_failure', 'policy',
                                    '2026-10-30T09:28:01.0000000Z', '2026-10-30T09:28:03Z', False]
                                   for identity in identifiers]}]}

    def test_exact_sorted_hash_and_latency(self):
        report = query.report_for(self.data(), query.timestamp('2026-10-30T09:28:00Z'))
        group = report['windowsCampaign']
        self.assertEqual(group['identitySetSha256'], hashlib.sha256(b'a\nb').hexdigest())
        self.assertEqual(group['distinctIds'], 2)
        self.assertEqual(group['ingestionLatencySeconds']['p99'], 2)

    def test_duplicates_remain_visible_and_window_is_scoped(self):
        group = query.report_for(self.data(('a','a')), query.timestamp('2026-10-30T09:28:02Z'))
        self.assertEqual(group['windowsCampaign']['rows'], 0)
        self.assertEqual(group['groups']['authentication_failure']['duplicateRows'], 1)

    def test_linux_campaign_excludes_prior_failed_attempt(self):
        data = self.data()
        for row in data['tables'][0]['rows']:
            row[1] = 'network_connection_denied'
        data['tables'][0]['rows'][0][3] = '2026-10-30T09:00:00Z'
        start = query.timestamp('2026-10-30T09:28:00Z')
        report = query.report_for(data, start, start)
        self.assertEqual(report['groups']['network_connection_denied']['rows'], 2)
        self.assertEqual(report['linuxCampaign']['rows'], 1)
        self.assertEqual(report['connectedSteady']['linux']['rows'], 1)

    def test_partial_and_malformed_results_fail(self):
        data = self.data()
        data['error'] = {'code':'PartialError'}
        with self.assertRaises(ValueError):
            query.report_for(data, dt.datetime.now(dt.timezone.utc))
        data = self.data()
        data['tables'][0]['rows'][0][-1] = 'false'
        with self.assertRaises(ValueError):
            query.report_for(data, dt.datetime.now(dt.timezone.utc))

    def test_missing_timezone_and_unexpected_columns_fail(self):
        with self.assertRaises(ValueError):
            query.timestamp('2026-10-30T09:28:00')
        data = self.data()
        data['tables'][0]['columns'].pop()
        with self.assertRaises(ValueError):
            query.report_for(data, dt.datetime.now(dt.timezone.utc))
