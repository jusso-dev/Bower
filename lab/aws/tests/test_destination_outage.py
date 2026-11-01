import importlib.util
import contextlib
import io
import json
import hashlib
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
module = types.ModuleType('destination_outage')
source = (ROOT / 'monitoring/destination-outage.sh').read_text().split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
exec(compile(source, 'destination-outage.sh', 'exec'), module.__dict__)
spec = importlib.util.spec_from_file_location('outage_plan', ROOT / 'monitoring/syslog-plan.py')
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


class DestinationOutageTests(unittest.TestCase):
    def environment(self):
        return {'BOWER_LAB_RUN': 'bower-ws6-20330518-000000', 'BOWER_PLAN_SHA256': 'a' * 64,
                'BOWER_LAB_BUCKET': 'bower-test-bucket', 'AWS_DEFAULT_REGION': 'ap-southeast-2',
                'BOWER_GENERATION_START_EPOCH': '2000000120'}

    def test_only_nonroot_bower_uid_outbound_443_in_both_families(self):
        scope = module.scope_from_environment(self.environment(), 2000000000)
        rules = module.rules_for(scope, 997)
        self.assertIn('table inet bower_outage_', rules)
        self.assertIn('hook output', rules)
        self.assertIn('meta skuid 997 tcp dport 443 drop', rules)
        self.assertNotIn('hook input', rules)
        self.assertNotIn('flush', rules)
        self.assertIn(scope['ownerComment'], rules)
        with self.assertRaises(ValueError):
            module.rules_for(scope, 0)

    def test_invalid_scope_and_late_schedule_fail(self):
        for field, value in [('BOWER_LAB_RUN', 'wrong'), ('BOWER_PLAN_SHA256', ';echo payload'),
                             ('BOWER_GENERATION_START_EPOCH', 'nan'), ('BOWER_GENERATION_START_EPOCH', '2000000010'),
                             ('BOWER_GENERATION_START_EPOCH', '2000010000'), ('AWS_DEFAULT_REGION', 'us-east-1')]:
            env = self.environment()
            env[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.scope_from_environment(env, 2000000000)

    def test_guard_is_armed_before_rule_and_restores_only_owned_table(self):
        self.assertLess(source.index("command('systemd-run'"), source.index("command('nft', '-f'"))
        self.assertIn("tables[0].get('comment') != scope['ownerComment']", module.RESTORE)
        self.assertIn("['nft', 'delete', 'table', 'inet', scope['table']]", module.RESTORE)
        self.assertIn("record['bootUnchanged'] and record['blockedSecondsLowerBound'] >= scope.get('outageSeconds', 3600)", module.RESTORE)
        compile(module.RESTORE, 'restore.py', 'exec')

    def test_outage_duration_defaults_to_one_hour_and_shorter_scenarios_are_bounded(self):
        scope = module.scope_from_environment(self.environment(), 2000000000)
        self.assertEqual((3600, 2000000120 + 3605), (scope['outageSeconds'], scope['restoreNotBeforeEpoch']))
        self.assertEqual('results/firewall/a-destination-outage/' + 'a' * 64 + '/fault', scope['resultPrefix'])
        env = dict(self.environment(), BOWER_LAB_RUN='bower-fw-20330518-000000', BOWER_OUTAGE_SECONDS='900',
                   BOWER_SCENARIO='a-relp-destination-outage')
        scope = module.scope_from_environment(env, 2000000000)
        self.assertEqual((900, 2000000120 + 905), (scope['outageSeconds'], scope['restoreNotBeforeEpoch']))
        self.assertEqual('results/firewall/a-relp-destination-outage/' + 'a' * 64 + '/fault', scope['resultPrefix'])
        for field, value in [('BOWER_OUTAGE_SECONDS', '599'), ('BOWER_OUTAGE_SECONDS', '3601'),
                             ('BOWER_SCENARIO', '../escape'), ('BOWER_SCENARIO', 'b-idle')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                module.scope_from_environment(dict(self.environment(), **{field: value}), 2000000000)

    def test_one_hour_generation_is_distinct_from_source_blackhole(self):
        catalogue = planner.load_catalogue(ROOT / 'scripts', '10.0.1.10', '10.0.1.11')
        plan = planner.plan(catalogue, 'a-destination-outage', ROOT / 'scripts', Path('/public/state.json'),
                            '10.0.1.10', '10.0.1.11', 2000000000)
        self.assertEqual(['nft:A:1000000:36000'], plan['expectedBlocks'])
        self.assertEqual(36000, plan['generations'][0]['count'])
        self.assertEqual(10, plan['generations'][0]['rate'])
        self.assertEqual(3600, plan['externalFaultRequirement']['minimumVerifiedDurationSeconds'])
        self.assertFalse(plan['externalFaultRequirement']['implementedByThisPlan'])
        self.assertFalse(plan['sentinelQualified'])
        self.assertNotEqual(catalogue['a-blackhole']['duration'], catalogue['a-destination-outage']['duration'])

    def test_restorer_removes_owned_table_and_reports_monotonic_duration(self):
        self.run_restorer(owner_matches=True)

    def test_restorer_refuses_foreign_table(self):
        self.run_restorer(owner_matches=False)

    def test_snapshot_restores_when_nft_omits_table_comments(self):
        self.run_snapshot_restorer(None)

    def test_snapshot_refuses_replaced_or_modified_table(self):
        for mutation in ('handle', 'rule', 'family', 'extra'):
            with self.subTest(mutation=mutation):
                self.run_snapshot_restorer(mutation)

    def run_snapshot_restorer(self, mutation):
        scope = module.scope_from_environment(self.environment(), 2000000000)
        entries = [{'table': {'family': 'inet', 'name': scope['table'], 'handle': 2}},
                   {'rule': {'family': 'inet', 'table': scope['table'], 'handle': 3,
                             'expr': [{'match': {'right': 992}}, {'drop': None}]}}]
        scope['tableSnapshotSha256'] = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if mutation == 'handle': entries[0]['table']['handle'] = 4
        if mutation == 'rule': entries[1]['rule']['expr'][0]['match']['right'] = 993
        if mutation == 'family': entries[0]['table']['family'] = 'ip'
        if mutation == 'extra': entries.append({'chain': {'name': 'foreign'}})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scope.json').write_text(json.dumps(scope))
            (root / 'applied.json').write_text(json.dumps({'appliedMonotonic': 300, 'bootId': 'synthetic-boot'}))
            listing = json.dumps({'nftables': [{'metainfo': {'version': '1.0.4'}}, *entries]})
            responses = [types.SimpleNamespace(returncode=0, stdout=listing), types.SimpleNamespace(returncode=0)]
            if mutation is None: responses.append(types.SimpleNamespace(returncode=0))
            original_read = Path.read_text
            def read(path, *args, **kwargs):
                return 'synthetic-boot' if str(path) == '/proc/sys/kernel/random/boot_id' else original_read(path, *args, **kwargs)
            with mock.patch.object(module.sys, 'argv', ['restore.py', str(root)]), \
                    mock.patch.object(module.subprocess, 'run', side_effect=responses) as commands, \
                    mock.patch.object(module.time, 'monotonic', side_effect=[4000, 4001]), \
                    mock.patch.object(Path, 'read_text', read), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(SystemExit) as stopped:
                exec(compile(module.RESTORE, 'restore.py', 'exec'), {})
            report = json.loads((root / 'restored.json').read_text())
            self.assertEqual(mutation is None, report['removed'])
            self.assertEqual(mutation is None, report['minimumDurationPassed'])
            self.assertEqual(0 if mutation is None else 1, stopped.exception.code)
            deletions = [call for call in commands.call_args_list if call.args[0][:2] == ['nft', 'delete']]
            self.assertEqual(1 if mutation is None else 0, len(deletions))
            if mutation is None:
                self.assertEqual('exact-installed-table-snapshot', report['ownershipCheck'])

    def test_missing_timing_evidence_preserves_removal_but_does_not_qualify(self):
        scope = module.scope_from_environment(self.environment(), 2000000000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scope.json').write_text(json.dumps(scope))
            listing = json.dumps({'nftables': [{'table': {'comment': scope['ownerComment']}}]})
            responses = [types.SimpleNamespace(returncode=0, stdout=listing),
                         types.SimpleNamespace(returncode=0), types.SimpleNamespace(returncode=0)]
            with mock.patch.object(module.sys, 'argv', ['restore.py', str(root)]), \
                 mock.patch.object(module.subprocess, 'run', side_effect=responses), \
                 mock.patch.object(module.time, 'monotonic', side_effect=[4000, 4001]), \
                 contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                exec(compile(module.RESTORE, 'restore.py', 'exec'), {})
            report = json.loads((root / 'restored.json').read_text())
            self.assertTrue(report['removed'])
            self.assertFalse(report['minimumDurationPassed'])
            self.assertEqual('FileNotFoundError', report['category'])
            self.assertEqual(1, stopped.exception.code)

    def run_restorer(self, owner_matches):
        scope = module.scope_from_environment(self.environment(), 2000000000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scope.json').write_text(json.dumps(scope))
            (root / 'applied.json').write_text(json.dumps({'appliedMonotonic': 300, 'bootId': 'synthetic-boot'}))
            listing = json.dumps({'nftables': [{'table': {'comment': scope['ownerComment'] if owner_matches else 'foreign'}}]})
            responses = [types.SimpleNamespace(returncode=0, stdout=listing), types.SimpleNamespace(returncode=0)]
            if owner_matches:
                responses.append(types.SimpleNamespace(returncode=0))
            original_read = Path.read_text

            def read(path, *args, **kwargs):
                return 'synthetic-boot' if str(path) == '/proc/sys/kernel/random/boot_id' else original_read(path, *args, **kwargs)

            with mock.patch.object(module.sys, 'argv', ['restore.py', str(root)]), \
                    mock.patch.object(module.subprocess, 'run', side_effect=responses) as commands, \
                    mock.patch.object(module.time, 'monotonic', side_effect=[4000, 4001]), \
                    mock.patch.object(Path, 'read_text', read), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(SystemExit) as stopped:
                exec(compile(module.RESTORE, 'restore.py', 'exec'), {})
            report = json.loads((root / 'restored.json').read_text())
            self.assertEqual(owner_matches, report['removed'])
            self.assertEqual(0 if owner_matches else 1, stopped.exception.code)
            deletes = [call.args[0] for call in commands.call_args_list if call.args[0][:2] == ['nft', 'delete']]
            self.assertEqual([['nft', 'delete', 'table', 'inet', scope['table']]] if owner_matches else [], deletes)
            if owner_matches:
                self.assertTrue(report['minimumDurationPassed'])
                self.assertEqual(3700, report['blockedSecondsLowerBound'])


if __name__ == '__main__':
    unittest.main()
