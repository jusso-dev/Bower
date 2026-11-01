"""Pure sampler checks: no service, token, HTTP, AWS or scheduler calls."""
import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'monitoring/sample-resources-linux.sh'
code = SOURCE.read_text().split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
sampler = types.ModuleType('sampler')
exec(compile(code, str(SOURCE), 'exec'), sampler.__dict__)


def scope():
    return {'runId': 'bower-ws6-20261101-011000', 'scope': 'outage', 'planSha256': 'a' * 64,
            'durationSeconds': 60, 'bootId': 'boot'}


def rows():
    return [{'sequence': i, 'at': '2026-11-01T00:00:00Z', 'elapsedSeconds': i * 15,
             'monotonicSeconds': i * 15 + 1000, 'bootId': 'boot', 'metricsAvailable': True,
             'process': {'pid': 1, 'startTicks': 123, 'residentBytes': i * 100, 'cpuPercentOfOneCore': i},
             'disk': {'availableBytes': 1000 - i * 10}, 'dbWalBytes': 10 + i,
             'queue': {'pending': i, 'count': i + 1, 'totalBytes': 50 + i, 'undeliveredBytes': i, 'deadLettered': 0},
             'sourceCounters': {key: i for key in sampler.SOURCE_FIELDS}} for i in range(5)]


class ResourceSamplingTests(unittest.TestCase):
    def test_projection_is_allow_list_and_aggregates(self):
        status = {'queue': {key: 1 for key in sampler.QUEUE_FIELDS},
                  'syslog': [{**{key: 2 for key in sampler.SOURCE_FIELDS}, 'payload': 'SECRET'}] * 2,
                  'token': 'SECRET', 'configuration': 'SECRET'}
        queue, counters = sampler.sanitized_status(status)
        self.assertEqual(queue['pending'], 3)
        self.assertEqual(queue['count'], 5)
        self.assertEqual(counters['dropped'], 4)
        self.assertNotIn('SECRET', json.dumps((queue, counters)))

    def test_invalid_or_missing_counters_fail_closed(self):
        for value in (True, -1, 1.1, '1', 2**63, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sampler.number(value)
        for sources in ([], [{}], [{}] * 33, {}):
            with self.subTest(sources=sources), self.assertRaises((ValueError, KeyError)):
                sampler.sanitized_status({'queue': {key: 0 for key in sampler.QUEUE_FIELDS}, 'syslog': sources})

    def test_summary_peaks_and_continuity(self):
        report = sampler.summary(scope(), rows(), True, 'boot')
        self.assertTrue(report['samplingComplete'])
        self.assertFalse(report['deliveryQualified'])
        self.assertEqual(report['peakProcessResidentBytes'], 400)
        self.assertEqual(report['minimumQueueVolumeAvailableBytes'], 960)
        self.assertEqual(report['peakPendingCount'], 4)
        self.assertEqual(report['sourceCounterIncreases']['dropped'], 4)
        self.assertEqual(report['maxSampleGapSeconds'], 15)
        self.assertEqual(report['processRestartCount'], 0)

    def test_incomplete_boot_gap_and_missing_samples_cannot_pass(self):
        self.assertFalse(sampler.summary(scope(), rows(), False, 'boot')['samplingComplete'])
        self.assertFalse(sampler.summary(scope(), rows(), True, 'new-boot')['samplingComplete'])
        self.assertFalse(sampler.summary(scope(), [], False, 'boot')['samplingComplete'])
        for case in ('failure', 'gap', 'late-start', 'short', 'boot-change'):
            fixtures = rows()
            if case == 'failure': fixtures[2]['metricsAvailable'] = False
            if case == 'gap': fixtures[-1]['monotonicSeconds'] += 31
            if case == 'late-start':
                for row in fixtures: row['elapsedSeconds'] += 50
            if case == 'short': fixtures = fixtures[:2]
            if case == 'boot-change': fixtures[-1]['bootId'] = 'other'
            with self.subTest(case=case):
                self.assertFalse(sampler.summary(scope(), fixtures, True, 'boot')['samplingComplete'])

    def test_resets_partial_peaks_and_missing_process_do_not_invent_restarts(self):
        fixtures = rows()
        fixtures[2]['sourceCounters']['dropped'] = 0
        fixtures[2]['process']['startTicks'] = 456
        fixtures[3]['metricsAvailable'] = False
        fixtures[3]['process']['residentBytes'] = 900
        del fixtures[4]['process']
        report = sampler.summary(scope(), fixtures, True, 'boot')
        self.assertEqual(report['sourceCounterResetCount'], 1)
        self.assertEqual(report['peakProcessResidentBytes'], 900)
        self.assertEqual(report['processRestartCount'], 2)

    def test_bad_sequence_and_clock_rejected(self):
        fixtures = rows(); fixtures[1]['sequence'] = 7
        with self.assertRaises(ValueError): sampler.summary(scope(), fixtures, True, 'boot')
        fixtures = rows(); fixtures[1]['monotonicSeconds'] = -1
        with self.assertRaises(ValueError): sampler.summary(scope(), fixtures, True, 'boot')

    def test_public_scope_validation(self):
        env = {'BOWER_LAB_RUN': scope()['runId'], 'BOWER_SAMPLE_SCOPE': 'outage', 'BOWER_PLAN_SHA256': 'a' * 64,
               'BOWER_LAB_BUCKET': 'owned-bucket', 'AWS_DEFAULT_REGION': 'ap-southeast-2'}
        self.assertEqual(sampler.scope_from_environment(env)['scope'], 'outage')
        for key, value in [('BOWER_LAB_RUN', '../other'), ('BOWER_SAMPLE_SCOPE', "outage';touch x"),
                           ('BOWER_PLAN_SHA256', 'a' * 63), ('BOWER_LAB_BUCKET', 'x/y'),
                           ('AWS_DEFAULT_REGION', 'us-east-1')]:
            with self.subTest(key=key), self.assertRaises(ValueError): sampler.scope_from_environment({**env, key: value})

    def test_bounded_jsonl_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'samples.jsonl'
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows()))
            self.assertEqual(len(sampler.load_rows(root)), 5)
            path.write_text('{}\n' * 482)
            with self.assertRaises(ValueError): sampler.load_rows(root)
            path.write_text(' ' * 8193 + '\n')
            with self.assertRaises(ValueError): sampler.load_rows(root)
            path.unlink(); (root / 'other').write_text('{}\n'); path.symlink_to(root / 'other')
            with self.assertRaises(ValueError): sampler.load_rows(root)

    def test_sample_failure_retains_resources_but_never_raw_error(self):
        process = {'pid': 12, 'startTicks': 5, 'cpuSeconds': 10, 'residentBytes': 500}
        previous = {'process': {**process, 'cpuSeconds': 5}, 'monotonicSeconds': 100}
        volume = types.SimpleNamespace(f_bavail=10, f_frsize=4096, f_blocks=100)
        with patch.object(sampler, 'boot', return_value='boot'), patch.object(sampler.time, 'monotonic', return_value=115), \
             patch.object(sampler, 'process_read', return_value=process), patch.object(sampler.os, 'statvfs', return_value=volume), \
             patch.object(sampler, 'status_read', side_effect=ValueError('SECRET')):
            result = sampler.sample(1, 100, previous)
        self.assertFalse(result['metricsAvailable'])
        self.assertAlmostEqual(result['process']['cpuPercentOfOneCore'], 100 / 3)
        self.assertEqual(result['disk']['availableBytes'], 40960)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_standalone_worker_does_not_contain_injected_ssm_environment(self):
        prefixed = "export BOWER_SAMPLE_SCOPE='outage'\n" + SOURCE.read_text()
        extracted = prefixed.split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        self.assertEqual(extracted, code)
        compile(extracted, 'worker.py', 'exec')


if __name__ == '__main__': unittest.main()
