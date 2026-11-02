import importlib.util
import os
from pathlib import Path
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


def sender_segments(seconds, smoke=False):
    """Runs only the schedule part of the sender worker, as the host does."""
    source = (ROOT / 'soak' / 'sender-generator.sh').read_text().split('# WORKER\n', 1)[1]
    schedule = source.split("(directory / 'plan.json')", 1)[0]
    scope = {}
    with mock.patch.object(sys, 'argv', ['w', '/tmp/x', 'label', '0', str(seconds), '0', '1' if smoke else '0']):
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

    def test_windows_generator_uses_the_same_schedule(self):
        text = (ROOT / 'soak' / 'generator-windows.ps1').read_text()
        self.assertIn('for ($b = 7200; $b + 60 -le $total; $b += 14400)', text)
        self.assertIn('$at += 7200', text)
        self.assertIn('return ,$segments', text)

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
