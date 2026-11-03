import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sender_segments(seconds, smoke=False, first=0):
    """Runs only the schedule and identity-range check of the sender worker, as the host does."""
    source = (ROOT / 'soak' / 'sender-generator.sh').read_text().split('# WORKER\n', 1)[1]
    schedule = source.split("(directory / 'plan.json')", 1)[0]
    scope = {}
    with mock.patch.object(sys, 'argv', ['w', '/tmp/x', 'label', '0', str(seconds), str(first), '1' if smoke else '0']):
        exec(schedule, scope)
    return scope['segments']


class SoakTests(unittest.TestCase):
    def test_schedule_is_steady_with_a_burst_every_four_hours(self):
        segments = sender_segments(86400)
        self.assertEqual(sum(length * rate for _, length, rate in segments), 896400)
        self.assertEqual([at for at, _, rate in segments if rate == 100], list(range(7200, 86400, 14400)))
        self.assertTrue(all(length <= 7200 and length * rate <= 100000 for _, length, rate in segments))
        self.assertEqual(sum(length for _, length, _ in segments), 86400)
        self.assertEqual(sender_segments(900, smoke=True), [(0, 900, 10)])

    def test_sender_refuses_identities_outside_the_track_a_rule(self):
        self.assertEqual(len(sender_segments(86400, first=100000)), 18)
        # The rule's identity space is 0..2,948,799 (syslog-host.py nft_ports, extended for the re-soak).
        self.assertEqual(len(sender_segments(86400, first=2948800 - 896400)), 18)
        for first in (-1, 2948800 - 896400 + 1):
            with self.assertRaises(SystemExit):
                sender_segments(86400, first=first)
        script = (ROOT / 'soak' / 'sender-generator.sh').read_text()
        self.assertIn('"$BOWER_SOAK_FIRST" =~ ^[0-9]+$', script)

    @unittest.skipUnless(shutil.which('pwsh'), 'pwsh is not installed')
    def test_windows_generator_runs_the_same_schedule(self):
        """Runs Get-Segments from generator-windows.ps1 and compares it with the sender's schedule."""
        text = (ROOT / 'soak' / 'generator-windows.ps1').read_text()
        function = text[text.index('function Get-Segments'):text.index('$dir = ')]
        for seconds, smoke in ((86400, False), (900, True), (30000, False), (7260, False)):
            command = (function + '\n$s = Get-Segments %d $%s\n' % (seconds, 'true' if smoke else 'false')
                       + "($s | ForEach-Object { '{0},{1},{2}' -f $_[0], $_[1], $_[2] }) -join ';'")
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command', command],
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            windows = [tuple(map(int, item.split(','))) for item in result.stdout.strip().split(';')]
            with self.subTest(seconds=seconds, smoke=smoke):
                self.assertEqual(windows, sender_segments(seconds, smoke))

    @unittest.skipUnless(shutil.which('pwsh'), 'pwsh is not installed')
    def test_soak_powershell_scripts_parse_unrendered(self):
        for path in sorted((ROOT / 'soak').glob('*.ps1')):
            command = ("$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$t,[ref]$e)"
                       "|Out-Null; exit $e.Count" % path)
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command', command],
                                    capture_output=True, text=True, timeout=120)
            with self.subTest(script=path.name):
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_soak_shell_scripts_pass_bash_syntax_check(self):
        for path in sorted((ROOT / 'soak').glob('*.sh')):
            with self.subTest(script=path.name):
                self.assertEqual(subprocess.run(['bash', '-n', str(path)], capture_output=True).returncode, 0)

    def test_firewall_identity_index_round_trips(self):
        reconcile = load('soak_reconcile', ROOT / 'soak' / 'reconcile.py')
        for index in (0, 39999, 40000, 100000, 996399, 1999999):
            (identity,) = reconcile.firewall_ids(index, 1)
            self.assertEqual(reconcile.index(identity), index)

    def test_soak_profile_template(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {'BOWER_LAB_RUN_ID': 'bower-soak-20261102-015614', 'BOWER_LAB_PROFILE': 'soak', 'BOWER_LAB_DIR': directory}
            with mock.patch.dict(os.environ, env):
                lab = load('soak_lab', ROOT / 'upgrade-recovery' / 'lab.py')
            self.assertEqual(lab.HOSTS, ['Dc', 'Wec', 'Linux', 'Sender'])
            self.assertEqual(lab.EXPIRY_HOURS, 30)
            responses = {'ssm': {'Parameter': {'Value': 'ami-1'}},
                         'describe-nat-gateways': {'NatGateways': [{'State': 'available', 'VpcId': lab.VPC, 'SubnetId': 's-1'}]},
                         'describe-subnets': {'Subnets': [{'SubnetId': 's-1', 'AvailabilityZone': 'a', 'CidrBlock': '172.31.0.0/20'}]}}
            lab.aws = lambda *args, **kwargs: responses['ssm' if args[0] == 'ssm' else args[1]]
            template = lab.build('2026-11-03T07:56:59')
        resources = template['Resources']
        self.assertEqual(resources['Sender']['Properties']['IamInstanceProfile'], {'Ref': 'SenderProfile'})
        statements = resources['SenderRole']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        self.assertEqual([s['Resource']['Fn::Sub'] for s in statements],
                         ['${Artifacts.Arn}/artifacts/qualification/bower-soak-20261102-015614/sender/*',
                          '${Artifacts.Arn}/results/sender/*'])
        self.assertIn('${Sender}', resources['Expiry']['Properties']['Target']['Input']['Fn::Sub'])
        self.assertEqual(resources['Linux']['Properties']['InstanceType'], 't3.small')

    def test_profile_and_run_id_must_agree(self):
        env = {'BOWER_LAB_RUN_ID': 'bower-ws4-20261102-015614', 'BOWER_LAB_PROFILE': 'soak', 'BOWER_LAB_DIR': '/tmp'}
        result = subprocess.run([sys.executable, str(ROOT / 'upgrade-recovery' / 'lab.py'), 'status'],
                                env={**os.environ, **env}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('does not match', result.stderr)


if __name__ == '__main__':
    unittest.main()


class ReconcileGateTests(unittest.TestCase):
    """Pass/fail logic of reconcile.py on small fixtures: incomplete or empty input never passes."""

    @classmethod
    def setUpClass(cls):
        cls.r = load('soak_reconcile_gates', ROOT / 'soak' / 'reconcile.py')

    def rows(self, ids, copies=1):
        return {i: {'EventId': i, 'Copies': copies} for i in ids}

    def test_compare_exact_missing_extra_duplicate_and_empty(self):
        compare = self.r.compare
        native = {'a', 'b', 'c'}
        self.assertTrue(compare(native, set(native), self.rows(native))['exact'])
        duplicates = {**self.rows({'a', 'b'}), 'c': {'EventId': 'c', 'Copies': 3}}
        result = compare(native, set(native), duplicates)
        self.assertTrue(result['exact'])
        self.assertEqual(result['duplicateRows'], 2)
        self.assertFalse(compare(native, {'a', 'b'}, self.rows(native))['exact'])          # missing at accepted
        extra = compare(native, native | {'z'}, self.rows(native))                         # extra at accepted
        self.assertFalse(extra['exact'])
        self.assertEqual(extra['extraAtAccepted'], 1)
        self.assertEqual(extra['acceptedSha256'], self.r.digest(native | {'z'}))
        self.assertFalse(compare(native, set(native), self.rows({'a', 'b'}))['exact'])     # missing at Sentinel
        self.assertFalse(compare(native, set(native), self.rows(native | {'y'}))['exact']) # extra at Sentinel
        self.assertFalse(compare(set(), set(), {})['exact'])                               # empty input
        self.assertFalse(compare(native, set(native), self.rows(native), native_complete=False)['exact'])

    def write_window(self, root, name, ids, selected=None, columns=4, sub='native', bounds=None):
        directory = root / 'hosts' / 'dc' / sub
        directory.mkdir(parents=True, exist_ok=True)
        lines = []
        for n, identity in enumerate(ids):
            fields = ['redacted-' + identity, str(n), str(n), identity][:columns]
            lines.append('\t'.join(fields))
        (directory / (name + ('.ids' if sub == 'native' else '.json.ids'))).write_text('\n'.join(lines) + '\n')
        if bounds is None:
            since = self.r.SOAK_START + int(name[1:]) * 3600
            bounds = (since, since + 3600)
        (directory / (name + '.json')).write_text(json.dumps({
            'since': self.r.iso(bounds[0]), 'until': self.r.iso(bounds[1]),
            'selected': len(ids) if selected is None else selected, 'distinct': len(set(ids)),
            'duplicateIdentities': 0, 'redactionChangedIds': 0, 'identitySetSha256': '0' * 64}))

    def test_windows_native_requires_every_window_original_ids_and_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_window(root, 'h00', ['winevt-1', 'winevt-2'])
            self.write_window(root, 'h01', ['winevt-3'], sub='manual')
            ids, meta = self.r.windows_native(root, ['h00', 'h01'], attempts=3)
            self.assertEqual(ids, {'winevt-1', 'winevt-2', 'winevt-3'})
            self.assertTrue(meta['complete'])
            _, missing = self.r.windows_native(root, ['h00', 'h01', 'h02'], attempts=3)
            self.assertFalse(missing['complete'])
            self.assertIn('missing-window-h02', missing['problems'])
            _, short = self.r.windows_native(root, ['h00', 'h01'], attempts=4)
            self.assertFalse(short['complete'])
            self.write_window(root, 'h02', ['winevt-3'])                       # same original id twice
            _, duplicated = self.r.windows_native(root, ['h00', 'h01', 'h02'], attempts=3)
            self.assertIn('duplicate-original-ids', duplicated['problems'])
            self.write_window(root, 'h03', ['winevt-4'], columns=3)            # redacted form only
            _, redacted = self.r.windows_native(root, ['h03'], attempts=1)
            self.assertFalse(redacted['complete'])
            self.write_window(root, 'h04', ['winevt-5'], selected=2)           # ids file shorter than report
            _, truncated = self.r.windows_native(root, ['h04'], attempts=1)
            self.assertIn('ids-file-incomplete-h04', truncated['problems'])
            _, empty = self.r.windows_native(root, [], attempts=0)
            self.assertFalse(empty['complete'])
            # An export whose UNTIL is not after SINCE, or that covers another hour, is not the window.
            start = self.r.SOAK_START + 5 * 3600
            self.write_window(root, 'h05', [], bounds=(start, start))
            self.assertIn('window-bounds-h05', self.r.windows_native(root, ['h05'])[1]['problems'])
            self.write_window(root, 'h06', ['winevt-6'], bounds=(start, start + 3600))
            self.assertIn('window-bounds-h06', self.r.windows_native(root, ['h06'], attempts=1)[1]['problems'])

    def write_segments(self, root, segments):
        directory = root / 'sender' / 'soak'
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / 'segments.jsonl').open('w') as stream:
            for number, (first, count, rate, delta) in enumerate(segments, 1):
                stream.write(json.dumps({'segment': number, 'first': first, 'count': count, 'rate': rate,
                                         'plannedStart': 0, 'requestedStart': 0, 'exitCode': 0,
                                         'generator': {'sent': count, 'nativeCounterDelta': {'A': delta}}}) + '\n')

    def planned(self):
        first, out = 100000, []
        for _, seconds, rate in self.r.schedule(86400):
            out.append((first, seconds * rate, rate, seconds * rate))
            first += seconds * rate
        return out

    def test_firewall_native_requires_the_whole_profile(self):
        end = self.r.SOAK_START + self.r.SOAK_SECONDS + 3600
        self.assertEqual(len(self.r.schedule(86400)), 18)
        self.assertEqual(self.r.profile('soak')['events'], 896400)
        self.assertEqual(len(self.r.profile('soak')['windows']), 25)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_segments(root, self.planned())
            ids, meta = self.r.firewall_native(root, 'soak', end)
            self.assertEqual(len(ids), 896400)
            self.assertTrue(meta['complete'])
            self.write_segments(root, [(100000, 1, 10, 1)])                   # 1 of 896,400
            ids, meta = self.r.firewall_native(root, 'soak', end)
            self.assertFalse(meta['complete'])
            self.assertFalse(self.r.compare(ids, set(ids), self.rows(ids), meta['complete'])['exact'])
            self.write_segments(root, self.planned()[:-1])                    # 17 of 18 segments
            self.assertFalse(self.r.firewall_native(root, 'soak', end)[1]['complete'])
            bad = self.planned()
            bad[3] = bad[3][:3] + (bad[3][3] - 1,)                            # counter one short
            self.write_segments(root, bad)
            self.assertIn('native-counter-or-sent-mismatch', self.r.firewall_native(root, 'soak', end)[1]['problems'])
            (root / 'sender' / 'soak' / 'segments.jsonl').unlink()           # empty input
            ids, meta = self.r.firewall_native(root, 'soak', end)
            self.assertFalse(meta['complete'])
            self.assertFalse(self.r.compare(ids, set(), {}, meta['complete'])['exact'])

    def test_accepted_scope_is_independent_of_the_native_set(self):
        union = {'a13-n4402x20000': '', 'a13-n4400x20000': '', 'a13-n4449x59999': '', 'collector-health-x': ''}
        # 4402x20000 is index 80,000: smoke range is 0..8,999, soak 100,000..996,399.
        self.assertEqual(self.r.scope_accepted('linux', union, 'smoke'), {'a13-n4400x20000'})
        self.assertEqual(self.r.scope_accepted('linux', union, 'soak'), set())
        wec = {'winevt-smoke': '2026-11-02T03:07:47.0119502+00:00', 'winevt-soak': '2026-11-02T04:00:00Z',
               'winevt-late': '2026-11-02 05:00:00', 'collector-health-y': '2026-11-02T04:00:00Z'}
        self.assertEqual(self.r.scope_accepted('windows', wec, 'smoke'), {'winevt-smoke'})
        self.assertEqual(self.r.scope_accepted('windows', wec, 'soak'), {'winevt-soak', 'winevt-late'})

    def test_sentinel_merges_an_id_spanning_two_chunks(self):
        chunks = [[{'EventId': 'e1', 'Copies': 1, 'Generated': '2026-11-02T04:34:59Z', 'FirstIngested': '2026-11-02T04:35:09Z'}],
                  [{'EventId': 'e1', 'Copies': 2, 'Generated': '2026-11-02T04:35:01Z', 'FirstIngested': '2026-11-02T04:35:05Z'},
                   {'EventId': 'e2', 'Copies': 1, 'Generated': '2026-11-02T04:35:02Z', 'FirstIngested': '2026-11-02T04:35:04Z'}]]

        class Verifier:
            def query(self, text):
                return chunks.pop(0), 'hash'

        start = self.r.SOAK_START + 3600 - 60
        rows, hours, latency, _ = self.r.sentinel(Verifier(), 'c', 't', start, start + 120, start + 600, chunk=60)
        self.assertEqual(set(rows), {'e1', 'e2'})
        self.assertEqual(rows['e1']['Copies'], 3)
        self.assertEqual(rows['e1']['Generated'], '2026-11-02T04:34:59Z')
        self.assertEqual(rows['e1']['FirstIngested'], '2026-11-02T04:35:05Z')
        self.assertEqual(latency['count'], 2)
        self.assertEqual(self.r.compare({'e1', 'e2'}, {'e1', 'e2'}, rows)['duplicateRows'], 2)

    def test_alerts_follow_pages_and_fail_closed(self):
        pages = {'u1': {'value': [{'properties': {'essentials': {'alertRule': '/x/rules/a', 'monitorCondition': 'Fired',
                                                                 'startDateTime': '2026-11-02T02:36:41Z'}}}],
                        'nextLink': 'u2'},
                 'u2': {'value': [{'properties': {'essentials': {'alertRule': '/x/rules/b', 'monitorCondition': 'Resolved',
                                                                 'startDateTime': '2026-11-01T00:00:00Z',
                                                                 'monitorConditionResolvedDateTime': '2026-11-01T01:00:00Z'}}}]}}

        def runner(url):
            return mock.Mock(returncode=0, stdout=json.dumps(pages[url]))
        self.assertEqual(len(self.r.arm_list('u1', runner)), 2)
        with self.assertRaises(RuntimeError):
            self.r.arm_list('u1', lambda url: mock.Mock(returncode=1, stdout=''))

        def both(url):
            return mock.Mock(returncode=0, stdout=json.dumps(pages['u1' if 'alerts' in url else 'u2']))
        state = {'group': 'rg', 'workspaceResourceId': '/w'}
        result = self.r.alerts(state, self.r.SOAK_START, self.r.SOAK_START + 86400, both)
        self.assertEqual(len(result['alerts']), 2)
        self.assertEqual([a['activeDuringRun'] for a in result['alerts']], [True, False])
        self.assertEqual(result['activeDuringRun'], 1)

    def test_growth_uses_hours_3_to_24_and_signed_projection(self):
        start = self.r.SOAK_START
        def sample(hour, rss, threads):
            return {'at': self.r.iso(start + hour * 3600), 'bootId': 'b',
                    'process': {'pid': 1, 'startTicks': 1, 'cpuSeconds': hour, 'rssBytes': rss, 'threads': threads,
                                'fds': 20, 'nRestarts': 0},
                    'files': {'queue.db': 1000}, 'disk': {'availableBytes': 1}}
        # Flat during hours 3-24, then a drain-hour spike that must not count.
        samples = [sample(h / 12, 100e6, 20 - h / 288) for h in range(0, 24 * 12)] + [sample(24.5, 500e6, 20)]
        result = self.r.resources(samples, 'linux', start, start + 86400)
        self.assertTrue(result['criterion3']['flat']['memoryBytes'])
        self.assertTrue(result['criterion3']['flat']['threads'])   # falling is not growth
        self.assertTrue(result['criterion3']['pass'])
        self.assertFalse(self.r.resources([], 'linux', start, start + 86400)['criterion3']['pass'])


class ReviewFixTests(unittest.TestCase):
    """CodeRabbit round on PR #170: latency over the reported set, CIDR guard, final-export order."""

    @classmethod
    def setUpClass(cls):
        cls.r = load('soak_reconcile_review', ROOT / 'soak' / 'reconcile.py')

    def test_sentinel_counts_and_latency_only_for_kept_ids(self):
        chunk = [{'EventId': 'a13-n4402x20000', 'Copies': 1, 'Generated': '2026-11-02T04:34:00Z', 'FirstIngested': '2026-11-02T04:34:05Z'},
                 {'EventId': 'a13-n4402x20001', 'Copies': 2, 'Generated': '2026-11-02T04:36:00Z', 'FirstIngested': '2026-11-02T04:46:00Z'}]

        class Verifier:
            def query(self, text):
                return list(chunk), 'hash'

        keep = lambda k: self.r.index(k) < 80001
        start = self.r.SOAK_START
        rows, hours, latency, _ = self.r.sentinel(Verifier(), 'c', 't', start, start + 3600, start + 7200, keep=keep)
        self.assertEqual(set(rows), {'a13-n4402x20000'})
        self.assertEqual((hours[0]['distinct'], hours[0]['rows']), (1, 1))
        self.assertEqual((latency['count'], latency['p99']), (1, 5.0))

    def test_lab_refuses_a_subnet_outside_the_generator_guard(self):
        for profile, run, cidr in (('soak', 'bower-soak-20261102-015614', '172.31.233.0/24'),
                                   ('ws4', 'bower-ws4-20261102-015614', '172.31.247.0/24')):
            env = {**os.environ, 'BOWER_LAB_RUN_ID': run, 'BOWER_LAB_PROFILE': profile, 'BOWER_LAB_DIR': '/tmp',
                   'BOWER_LAB_CIDR': cidr}
            result = subprocess.run([sys.executable, str(ROOT / 'upgrade-recovery' / 'lab.py'), 'status'],
                                    env=env, capture_output=True, text=True)
            with self.subTest(profile=profile):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('generator guard', result.stderr)

    def collector_worker(self, directory):
        text = (ROOT / 'soak' / 'collector-agent.sh').read_text()
        source = text.split('\n# WORKER\n', 1)[1].rsplit('\nWORKER\n', 1)[0]
        source = source.rsplit('\nmain(sys.argv[1])', 1)[0]
        env = {'BOWER_LAB_RUN': 'bower-soak-20261102-015614', 'BOWER_LAB_BUCKET': 'b',
               'BOWER_SOAK_START': '1793590500', 'BOWER_SOAK_SECONDS': '86400'}
        scope = {'__name__': 'collector_worker'}
        with mock.patch.dict(os.environ, env):
            exec(source, scope)
        scope['DIR'] = Path(directory)
        scope['sample'] = lambda: {}
        scope['union'] = lambda: {}
        scope['print'] = lambda *args, **kwargs: None
        return scope

    def test_collector_final_marker_only_after_the_data_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = self.collector_worker(directory)
            worker['upload'] = mock.Mock(side_effect=RuntimeError('s3 down'))
            with self.assertRaises(RuntimeError):
                worker['main']('final')
            self.assertFalse((Path(directory) / 'final.json').exists())  # the next tick retries
            calls = []
            worker['upload'] = lambda names=('samples.jsonl', 'union.jsonl', 'accepted.tsv.gz'): (
                calls.append((tuple(names), (Path(directory) / 'final.json').exists())) or {})
            with mock.patch.object(worker['subprocess'], 'run'):
                worker['main']('final')
            self.assertEqual(calls, [(('samples.jsonl', 'union.jsonl', 'accepted.tsv.gz'), False), (('final.json',), True)])

    def test_windows_agents_mark_completion_after_upload(self):
        wec = (ROOT / 'soak' / 'wec-agent.ps1').read_text()
        final = wec[wec.index("if ($Action -eq 'final')"):]
        self.assertIn('Test-Path "$dir\\published.json"', wec)
        self.assertLess(final.index('Upload'), final.index('published.json'))
        dc = (ROOT / 'soak' / 'dc-agent.ps1').read_text()
        tick = dc[dc.index("if ($Action -eq 'tick')"):]
        self.assertIn('Test-Path "$out.uploaded"', tick)
        self.assertLess(tick.index('Put "$out.ids"'), tick.index('Set-Content "$out.uploaded"'))
