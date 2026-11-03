"""The 72-hour re-soak harness: pre-registration, schedule, identity space, host fault agent and
the fault accounting of the reconciler. No cloud access."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
PLAN = json.loads((ROOT / 'resoak' / 'preregistration.json').read_text())
RUN = 'bower-resoak-20261103-094057'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sender_segments(seconds, first=0):
    source = (ROOT / 'soak' / 'sender-generator.sh').read_text().split('# WORKER\n', 1)[1]
    schedule = source.split("(directory / 'plan.json')", 1)[0]
    scope = {}
    with mock.patch.object(sys, 'argv', ['w', '/tmp/x', 'label', '0', str(seconds), str(first), '0']):
        exec(schedule, scope)
    return scope['segments']


class PreregistrationTests(unittest.TestCase):
    def test_criteria_are_the_07_guide_table_verbatim(self):
        text = (REPO / 'docs/production-readiness/07-soak-and-release-validation.md').read_text()
        table = re.search(r'^\| # \| Criterion \| How it is measured \| Pass \|\n(?:^\|.*\n){7}', text, re.M).group(0)
        rows = table.splitlines()
        self.assertEqual([c['verbatim'] for c in PLAN['criteria']], rows[2:])
        self.assertEqual(PLAN['criteriaSource']['tableSha256'], __import__('hashlib').sha256(table.encode()).hexdigest())
        self.assertEqual(PLAN['latencyP99LimitSeconds'], {'linux': 13.3, 'windows': 18.16})
        self.assertEqual(PLAN['growth']['limitPercentOfMeanFor720Hours'], 10)

    def test_profile_is_72_hours_of_the_07_load(self):
        profile = PLAN['profile']
        segments = sender_segments(profile['soakSeconds'], profile['firewallSoakFirst'])
        self.assertEqual(profile['soakSeconds'], 72 * 3600)
        self.assertEqual(sum(n * r for _, n, r in segments), profile['eventsPerCollector'])
        self.assertEqual(len([s for s in segments if s[2] == 100]), 18)

    def test_every_requested_fault_is_scheduled_or_explicitly_skipped(self):
        kinds = {f['kind'] for f in PLAN['faults']}
        self.assertTrue({'collector-kill', 'destination-outage', 'host-reboot', 'sender-restart', 'log-rollover',
                         'credential-rotation-ingestion', 'credential-rotation-syslog-tls'} <= kinds)
        self.assertEqual([s['kind'] for s in PLAN['skipped']], ['sentinel-throttling'])
        kills = [f for f in PLAN['faults'] if f['kind'] == 'collector-kill']
        self.assertEqual(sorted(c for f in kills for c in f['collectors']), ['linux', 'windows'])
        reboots = [f for f in PLAN['faults'] if f['kind'] == 'host-reboot']
        self.assertEqual(sorted(f['hosts'][0] for f in reboots), ['Linux', 'Wec'])
        outage = next(f for f in PLAN['faults'] if f['kind'] == 'destination-outage')
        self.assertEqual(outage['durationSeconds'], 1800)

    def test_schedule_keeps_the_growth_windows_and_bursts_clear(self):
        seconds = PLAN['profile']['soakSeconds']
        bursts = [b for b in range(7200, seconds - 59, 14400)]
        for f in PLAN['faults']:
            with self.subTest(fault=f['id']):
                self.assertEqual(f['at'] % 3600, 1200)              # +h:20, clear of hh:00 retention with an hh:05 start
                self.assertTrue(all(abs(f['at'] - b) >= 900 for b in bursts))
                self.assertLess(f['at'] + f.get('durationSeconds', 0) + f['impactAllowanceSeconds'], seconds)
                self.assertEqual(sorted(f['reboots']), sorted(set(f['reboots']) & set(f['restarts'])))
        restarting = [f for f in PLAN['faults'] if f['restarts']]
        # Window (a), hours 3-24, has no restart; window (b) starts 3 h after the last restart.
        self.assertTrue(all(f['at'] >= 24 * 3600 for f in restarting))
        self.assertGreaterEqual(seconds - (max(f['at'] for f in restarting) + 3 * 3600), 21 * 3600)
        # The destination outage ends before the growth windows start.
        outage = next(f for f in PLAN['faults'] if f['kind'] == 'destination-outage')
        self.assertLess(outage['at'] + outage['durationSeconds'] + outage['impactAllowanceSeconds'], 3 * 3600 + 1)
        ids = [f['id'] for f in PLAN['faults']]
        self.assertEqual(len(ids), len(set(ids)))
        never = {'syslog-tls-expiry', 'destination-credential'}
        self.assertFalse(any(never & set(f['alertsPermitted']) for f in PLAN['faults']))


class IdentitySpaceTests(unittest.TestCase):
    def test_extended_firewall_ids_agree_between_generator_and_reconciler(self):
        host = load('syslog_host', ROOT / 'scripts' / 'syslog-host.py')
        reconcile = load('soak_reconcile', ROOT / 'soak' / 'reconcile.py')
        for index in (0, 39999, 1999999, 2000000, 2018975, 2018976, 2789199, 2948799):
            port, source = host.nft_ports(4400, index)
            identity = 'a13-n%dx%d' % (port, source)
            with self.subTest(index=index):
                self.assertEqual(reconcile.firewall_id(index), identity)
                self.assertEqual(reconcile.index(identity), index)
                self.assertTrue(4400 <= port <= 4449 and 1024 <= source <= 59999)
        self.assertEqual(host.nft_ports(4400, 999), (4400, 20999))     # unchanged below 2,000,000
        with self.assertRaises(ValueError):
            host.nft_ports(4400, 2948800)
        ids = reconcile.firewall_ids(100000, 2689200)
        self.assertEqual(len(ids), 2689200)                              # unique across the whole soak

    def test_sender_accepts_the_72_hour_range_and_refuses_beyond_it(self):
        self.assertEqual(len(sender_segments(259200, first=100000)), 54)
        with self.assertRaises(SystemExit):
            sender_segments(259200, first=2948800 - 2689200 + 1)

    def test_canary_ids_are_outside_the_bulk_scope(self):
        reconcile = load('soak_reconcile', ROOT / 'soak' / 'reconcile.py')
        canary = 'a13-n4399x20000'
        self.assertTrue(reconcile.FIREWALL_ID.fullmatch(canary))
        self.assertLess(reconcile.index(canary), 0)                      # never inside [first, first + events)


class LabProfileTests(unittest.TestCase):
    def template(self, extra=None):
        with tempfile.TemporaryDirectory() as directory:
            env = {'BOWER_LAB_RUN_ID': RUN, 'BOWER_LAB_PROFILE': 'resoak', 'BOWER_LAB_DIR': directory,
                   'BOWER_LAB_CIDR': '172.31.248.0/24', **(extra or {})}
            with mock.patch.dict(os.environ, env):
                lab = load('resoak_lab', ROOT / 'upgrade-recovery' / 'lab.py')
            responses = {'ssm': {'Parameter': {'Value': 'ami-1'}},
                         'describe-nat-gateways': {'NatGateways': [{'State': 'available', 'VpcId': lab.VPC, 'SubnetId': 's-1'}]},
                         'describe-subnets': {'Subnets': [{'SubnetId': 's-1', 'AvailabilityZone': 'a', 'CidrBlock': '172.31.0.0/20'}]}}
            lab.aws = lambda *args, **kwargs: responses['ssm' if args[0] == 'ssm' else args[1]]
            return lab, lab.build('2026-11-06T17:43:08')

    def test_fixed_performance_hosts_80_hour_guard_and_identity_bucket(self):
        lab, template = self.template()
        resources = template['Resources']
        self.assertEqual(lab.EXPIRY_HOURS, 80)
        for host in ('Dc', 'Wec', 'Linux', 'Sender'):
            properties = resources[host]['Properties']
            self.assertEqual(properties['InstanceType'], 'm6i.large')
            self.assertNotIn('CreditSpecification', properties)
            self.assertEqual(properties['MetadataOptions']['HttpTokens'], 'required')
            self.assertFalse(properties['NetworkInterfaces'][0]['AssociatePublicIpAddress'])
        self.assertEqual(resources['Artifacts']['Properties']['LifecycleConfiguration']['Rules'][0]['ExpirationInDays'], 7)
        host_policy = resources['HostRole']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        self.assertIn({'Effect': 'Allow', 'Action': ['s3:PutObject'], 'Resource': 'arn:aws:s3:::' + RUN + '-ids/hosts/*'}, host_policy)
        sender_policy = resources['SenderRole']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        self.assertEqual(sender_policy[-1]['Resource'], 'arn:aws:s3:::' + RUN + '-ids/sender/*')
        self.assertEqual(resources['Group']['Properties']['SecurityGroupIngress'], [])

    def test_expiry_override_only_shortens(self):
        self.assertEqual(self.template({'BOWER_LAB_EXPIRY_HOURS': '12'})[0].EXPIRY_HOURS, 12)
        self.assertEqual(self.template({'BOWER_LAB_EXPIRY_HOURS': '500'})[0].EXPIRY_HOURS, 80)


class FaultAgentTests(unittest.TestCase):
    def worker(self, directory, host, start, faults):
        text = (ROOT / 'resoak' / 'fault-agent.sh').read_text()
        source = text.split('\n# WORKER\n', 1)[1].rsplit('\nWORKER\n', 1)[0]
        source = source.rsplit("\n{'setup': setup", 1)[0].replace("DIR = Path('/var/lib/bower-lab/resoak')", 'DIR = Path(%r)' % directory)
        plan = dict(PLAN, faults=faults)
        Path(directory, 'plan.json').write_text(json.dumps(plan))
        env = {'BOWER_LAB_RUN': RUN, 'BOWER_LAB_BUCKET': 'b', 'BOWER_EVIDENCE_BUCKET': RUN + '-ids',
               'RESOAK_HOST': host, 'RESOAK_START': str(start)}
        scope = {'__name__': 'fault_agent'}
        with mock.patch.dict(os.environ, env):
            exec(source, scope)
        scope['upload'] = lambda names: None
        scope['boot_id'] = lambda: 'boot-1'
        scope['collector'] = lambda: {'pid': 1}
        return scope

    def test_due_faults_run_once_late_faults_are_missed_not_run(self):
        with tempfile.TemporaryDirectory() as directory:
            now = 1_800_000_000
            faults = [dict(PLAN['faults'][2], id='T1', at=0), dict(PLAN['faults'][2], id='T2', at=3600)]  # log rollover
            w = self.worker(directory, 'Linux', now - 30, faults)
            calls = []
            w['act'] = lambda fault, at: calls.append(fault['id']) or {'ok': True}
            w['now'] = lambda: __import__('datetime').datetime.fromtimestamp(now, __import__('datetime').timezone.utc)
            w['tick']()
            w['tick']()
            self.assertEqual(calls, ['T1'])
            records = [json.loads(l) for l in Path(directory, 'faults.jsonl').read_text().splitlines()]
            self.assertEqual([(r['fault'], r['step']) for r in records], [('T1', 'done')])
            w2 = self.worker(directory, 'Linux', now - 3600 - 601, faults)   # T2 is now 601 s late
            w2['act'] = lambda fault, at: calls.append(fault['id']) or {}
            w2['now'] = w['now']
            w2['tick']()
            self.assertEqual(calls, ['T1'])
            records = [json.loads(l) for l in Path(directory, 'faults.jsonl').read_text().splitlines()]
            self.assertEqual(records[-1]['step'], 'missed')

    def test_faults_for_other_hosts_are_ignored_and_failures_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            now = 1_800_000_000
            faults = [dict(PLAN['faults'][5], id='W1', at=0), dict(PLAN['faults'][4], id='L1', at=0)]  # Wec kill, Linux kill
            w = self.worker(directory, 'Linux', now - 10, faults)
            w['now'] = lambda: __import__('datetime').datetime.fromtimestamp(now, __import__('datetime').timezone.utc)
            w['act'] = mock.Mock(side_effect=RuntimeError('boom'))
            w['tick']()
            self.assertEqual([c.args[0]['id'] for c in w['act'].call_args_list], ['L1'])
            record = json.loads(Path(directory, 'faults.jsonl').read_text())
            self.assertEqual((record['step'], record['error']), ('failed', 'RuntimeError:boom'))

    @unittest.skipUnless(shutil.which('pwsh'), 'pwsh is not installed')
    def test_resoak_powershell_parses_unrendered(self):
        for path in sorted((ROOT / 'resoak').glob('*.ps1')):
            command = ("$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$t,[ref]$e)"
                       "|Out-Null; exit $e.Count" % path)
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, timeout=120)
            with self.subTest(script=path.name):
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_resoak_shell_scripts_pass_bash_syntax_check(self):
        for path in sorted((ROOT / 'resoak').glob('*.sh')):
            with self.subTest(script=path.name):
                self.assertEqual(subprocess.run(['bash', '-n', str(path)], capture_output=True).returncode, 0)


class AccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = load('resoak_reconcile', ROOT / 'resoak' / 'reconcile.py')
        cls.r.base.SOAK_START = 1_000_000

    def window(self, fid, start, end, collectors=('linux',), restarts=(), reboots=(), permitted=(), required=()):
        return {'id': fid, 'kind': 'x', 'start': start, 'end': end, 'impactEnd': end + 900, 'alertEnd': end + 900 + 3600,
                'collectors': list(collectors), 'restarts': list(restarts), 'reboots': list(reboots),
                'alertsPermitted': list(permitted), 'alertsRequiredAnyOf': list(required)}

    def test_latency_excludes_only_events_inside_fault_windows(self):
        iso = self.r.base.iso
        rows = {'a': {'Generated': iso(1_000_100), 'FirstIngested': iso(1_000_105)},
                'b': {'Generated': iso(1_002_000), 'FirstIngested': iso(1_003_800)},   # inside the outage: 1,800 s
                'c': {'Generated': iso(1_010_000), 'FirstIngested': iso(1_010_030)}}  # outside: 30 s
        result = self.r.latency_accounting(rows, [self.window('F01', 1_001_900, 1_003_700)], 13.3)
        self.assertEqual(result['outsideFaultWindows']['count'], 2)
        self.assertFalse(result['pass'])                  # the 30 s event outside any window still fails
        self.assertEqual(result['perFault']['F01']['max'], 1800.0)
        rows.pop('c')
        self.assertTrue(self.r.latency_accounting(rows, [self.window('F01', 1_001_900, 1_003_700)], 13.3)['pass'])

    def sample(self, at, pid, boot='b1'):
        return {'at': self.r.base.iso(at), 'bootId': boot, 'process': {'pid': pid, 'startTicks': pid}}

    def test_restarts_must_match_scheduled_faults_exactly(self):
        windows = [self.window('F05', 1_100_000, 1_100_000, restarts=['linux'])]
        good = [self.sample(1_000_000, 1), self.sample(1_100_300, 2)]
        self.assertTrue(self.r.restarts_accounting(good, 'linux', windows, 1_000_000, 1_200_000)['pass'])
        stray = good + [self.sample(1_150_000, 3)]
        result = self.r.restarts_accounting(stray, 'linux', windows, 1_000_000, 1_200_000)
        self.assertFalse(result['pass'])
        self.assertEqual(len(result['unexplained']), 1)
        missing = [self.sample(1_000_000, 1), self.sample(1_150_000, 1)]   # the scheduled kill did not restart it
        self.assertFalse(self.r.restarts_accounting(missing, 'linux', windows, 1_000_000, 1_200_000)['pass'])

    def test_alerts_are_excused_only_by_a_permitting_fault_window(self):
        run = RUN
        windows = [self.window('F01', 1_000_000, 1_001_800, permitted=['queue-backlog'], required=['queue-backlog'])]
        item = lambda rule, started: {'name': run + '-' + rule, 'state': 'Resolved', 'startedAt': self.r.base.iso(started),
                                      'resolvedAt': self.r.base.iso(started + 600), 'activeDuringRun': True}
        alerts = {'alerts': [item('queue-backlog', 1_001_000)], 'incidents': []}
        self.assertTrue(self.r.alerts_accounting(alerts, windows, run)['pass'])
        for rule, started in (('queue-backlog', 1_100_000), ('source-overdue', 1_001_000), ('syslog-tls-expiry', 1_001_000)):
            with self.subTest(rule=rule):
                result = self.r.alerts_accounting({'alerts': [item(rule, started)], 'incidents': []}, windows, run)
                self.assertFalse(result['pass'])
        incident = {'alerts': [], 'incidents': [dict(item('x', 1_001_000), name='incident')]}
        self.assertFalse(self.r.alerts_accounting(incident, windows, run)['pass'])


if __name__ == '__main__':
    unittest.main()
