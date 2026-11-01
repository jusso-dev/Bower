"""Offline safety tests for the disposable Azure lab helper."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('azure_environment', Path(__file__).with_name('azure-environment.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class AzureEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'azure-state.json'
        self.run = 'bower-val-261031123456-1234abcd'
        self.state = {'run': self.run, 'group': 'rg-' + self.run,
                      'workspaceName': self.run + '-logs', 'subscription': lab.SUB,
                      'tenant': lab.TENANT, 'identities': {}}

    def test_atomic_state_is_private_and_replaced(self):
        lab.atomic_json(self.path, self.state)
        self.state['note'] = 'updated'
        lab.atomic_json(self.path, self.state)
        self.assertEqual('updated', json.loads(self.path.read_text())['note'])
        self.assertEqual(0o600, self.path.stat().st_mode & 0o777)
        self.assertEqual([self.path], list(self.root.iterdir()))

    def test_group_ownership_rejects_other_run(self):
        with mock.patch.object(lab, 'az', return_value={'tags': {'Project': lab.PROJECT, 'RunId': 'different'}}):
            with self.assertRaisesRegex(RuntimeError, 'ownership'):
                lab.group_owned(self.state)

    def test_prepare_accepts_only_an_owning_aws_run_id(self):
        for run in ('bower-fw-20261101-120000; rm', 'rg-bower-fw-20261101-120000', 'bower-xx-20261101-120000'):
            with self.subTest(run=run), self.assertRaisesRegex(ValueError, 'Invalid Azure run id'):
                lab.prepare(self.root, self.path, run)
        self.assertTrue(lab.re.fullmatch(lab.RUN_PATTERN, 'bower-fw-20261101-120000'))
        self.assertTrue(lab.re.fullmatch(lab.RUN_PATTERN, self.run))

    def test_prepare_refuses_preexisting_group_before_writing_state(self):
        with mock.patch.object(lab, 'az', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'already exists'):
                lab.prepare(self.root, self.path)
        self.assertFalse(self.path.exists())

    def test_reconciles_interrupted_app_and_cleans_all_owned_items(self):
        name = self.run + '-ingest'
        app_id = '11111111-1111-4111-8111-111111111111'
        app_object = '22222222-2222-4222-8222-222222222222'
        principal = '33333333-3333-4333-8333-333333333333'
        self.state['identities']['ingest'] = {'name': name, 'nameChecked': True, 'creationAttempted': True}
        (self.root / 'ingest-key.pem').write_text('synthetic')
        app_present, sp_present, group_present = [True], [True], [True]
        calls = []

        def fake_az(*args):
            calls.append(args)
            if args[:3] == ('ad', 'app', 'list'):
                return [{'displayName': name, 'appId': app_id, 'id': app_object}] if app_present[0] else []
            if args[:3] == ('ad', 'sp', 'list'):
                return [{'appId': app_id, 'id': principal}] if sp_present[0] else []
            if args[:3] == ('ad', 'sp', 'delete'):
                sp_present[0] = False
                return None
            if args[:3] == ('ad', 'app', 'delete'):
                app_present[0] = False
                return None
            if args[:2] == ('group', 'exists'):
                return group_present[0]
            if args[:2] == ('group', 'show'):
                return {'tags': {'Project': lab.PROJECT, 'RunId': self.run}}
            if args[:2] == ('group', 'delete'):
                group_present[0] = False
                return None
            if args[:3] == ('role', 'assignment', 'list'):
                return []
            if args[:1] == ('rest',) and args[4].startswith(lab.GRAPH_DELETED):
                object_id = args[4][len(lab.GRAPH_DELETED):]
                if args[2] == 'delete':
                    purged.add(object_id)
                    return None
                if object_id in purged:
                    raise RuntimeError('not found')
                return {'id': object_id}
            raise AssertionError(args)

        purged = set()
        with mock.patch.object(lab, 'az', side_effect=fake_az):
            self.assertEqual({'cleaned': True}, lab.cleanup(self.root, self.path, self.state, 0))
        self.assertEqual({app_object, principal}, purged)
        self.assertEqual(app_id, self.state['identities']['ingest']['appId'])
        self.assertFalse((self.root / 'ingest-key.pem').exists())
        self.assertTrue(any(call[:3] == ('ad', 'sp', 'delete') for call in calls))
        self.assertTrue(any(call[:3] == ('role', 'assignment', 'list') for call in calls))

    def test_cleanup_continues_and_removes_keys_on_ownership_mismatch(self):
        name = self.run + '-ingest'
        self.state['identities']['ingest'] = {'name': name, 'nameChecked': True}
        key = self.root / 'ingest-key.pem'
        key.write_text('synthetic')
        calls = []

        def fake_az(*args):
            calls.append(args)
            if args[:3] == ('ad', 'app', 'list'):
                return []
            if args[:2] == ('group', 'exists'):
                return True
            if args[:2] == ('group', 'show'):
                return {'tags': {'Project': 'other', 'RunId': self.run}}
            raise AssertionError(args)

        with mock.patch.object(lab, 'az', side_effect=fake_az):
            with self.assertRaisesRegex(RuntimeError, 'ownership mismatch'):
                lab.cleanup(self.root, self.path, self.state, 0)
        self.assertFalse(key.exists())
        self.assertFalse(any(call[:2] == ('group', 'delete') for call in calls))
        self.assertTrue(json.loads(self.path.read_text())['cleanupErrors'])

    def test_cleanup_does_not_adopt_app_when_creation_was_not_attempted(self):
        name = self.run + '-ingest'
        self.state['identities']['ingest'] = {'name': name, 'nameChecked': True}
        app = {'displayName': name, 'appId': '11111111-1111-4111-8111-111111111111',
               'id': '22222222-2222-4222-8222-222222222222'}
        with mock.patch.object(lab, 'exact_apps', return_value=[app]), \
             mock.patch.object(lab, 'az', return_value=False) as az:
            with self.assertRaisesRegex(RuntimeError, 'ingest cleanup failed'):
                lab.cleanup(self.root, self.path, self.state, 0)
        self.assertNotIn('appId', self.state['identities']['ingest'])
        self.assertFalse(any(call.args[:3] in (('ad', 'app', 'delete'), ('ad', 'sp', 'delete'))
                             for call in az.call_args_list))

    def test_assignment_filter_excludes_shared_scope(self):
        principal = '33333333-3333-4333-8333-333333333333'
        base = '/subscriptions/' + lab.SUB + '/resourceGroups/' + self.state['group']
        grants = [{'scope': base + '/providers/Microsoft.Insights/x'},
                  {'scope': '/subscriptions/' + lab.SUB + '/resourceGroups/shared'}]
        with mock.patch.object(lab, 'az', return_value=grants):
            self.assertEqual([grants[0]], lab.owned_assignments(self.state, principal))

    def test_local_cleanup_does_not_follow_cache_symlink(self):
        shared = self.root / 'shared-cache'
        shared.mkdir()
        preserved = shared / 'token-cache'
        preserved.write_text('synthetic-existing-cache')
        cache = self.root / 'azure-cli-verifier'
        cache.symlink_to(shared, target_is_directory=True)
        self.assertEqual([], lab.local_cleanup(self.root))
        self.assertFalse(cache.is_symlink())
        self.assertEqual('synthetic-existing-cache', preserved.read_text())

    def test_default_azure_cache_and_children_cannot_be_state_directory(self):
        home = self.root / 'home'
        azure = home / '.azure'
        azure.mkdir(mode=0o700, parents=True)
        marker = azure / 'keep'
        marker.write_text('synthetic-default-cache')
        with mock.patch.object(lab.Path, 'home', return_value=home):
            for path in (azure, azure / 'child'):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'default Azure CLI'):
                    lab.secure_dir(path)
        self.assertEqual('synthetic-default-cache', marker.read_text())

    def test_untracked_interrupted_creation_is_not_reported_clean(self):
        self.state['identities']['ingest'] = {
            'name': self.run + '-ingest', 'nameChecked': True, 'creationAttempted': True,
        }
        with mock.patch.object(lab, 'exact_apps', return_value=[]), \
             mock.patch.object(lab, 'az', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'ingest cleanup failed'):
                lab.cleanup(self.root, self.path, self.state, 0)

    def test_mutations_require_explicit_apply_before_azure_calls(self):
        result = subprocess.run([sys.executable, str(Path(lab.__file__)), 'prepare',
                                 '--state-dir', str(self.root)], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('requires --apply', result.stderr)
        self.assertFalse(self.path.exists())

    def test_prepare_refuses_existing_credentials_without_removing_them(self):
        key = self.root / 'ingest-key.pem'
        key.write_text('not-ours')
        result = subprocess.run([sys.executable, str(Path(lab.__file__)), 'prepare',
                                 '--state-dir', str(self.root), '--apply'], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('existing lab files', result.stderr)
        self.assertEqual('not-ours', key.read_text())

    def test_transient_noncleanup_failure_preserves_campaign_credentials(self):
        lab.atomic_json(self.path, self.state)
        key = self.root / 'ingest-key.pem'
        key.write_text('synthetic-campaign-key')
        for action in ('status', 'plan', 'apply', 'sentinel'):
            argv = ['azure-environment.py', action, '--state-dir', str(self.root)]
            if action in ('apply', 'sentinel'):
                argv.append('--apply')
            with self.subTest(action=action), mock.patch.object(sys, 'argv', argv), \
                 mock.patch.object(lab, 'account', side_effect=RuntimeError('synthetic-auth-failure')), \
                 mock.patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
                lab.main()
            self.assertEqual('synthetic-campaign-key', key.read_text())

    def test_explicit_cleanup_failure_still_removes_local_credentials(self):
        lab.atomic_json(self.path, self.state)
        key = self.root / 'ingest-key.pem'
        key.write_text('synthetic-campaign-key')
        argv = ['azure-environment.py', 'cleanup', '--state-dir', str(self.root), '--apply']
        with mock.patch.object(sys, 'argv', argv), \
             mock.patch.object(lab, 'account', side_effect=RuntimeError('synthetic-auth-failure')), \
             mock.patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
            lab.main()
        self.assertFalse(key.exists())

    def test_documented_private_staging_removal_preserves_external_evidence(self):
        readme = Path(__file__).with_name('README.md').read_text()
        script = readme.split("python3 - <private-staging-root> <sanitized-evidence-directory> <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory(prefix='bower-cleanup-doc-', dir='/tmp') as staging, \
             tempfile.TemporaryDirectory(prefix='bower-evidence-doc-', dir='/tmp') as preserved:
            root, evidence = Path(staging), Path(preserved)
            (root / 'state.json').write_text(json.dumps({'account': '959038055523'}))
            (root / 'azure-state.json').write_text(json.dumps({
                'subscription': lab.SUB, 'tenant': lab.TENANT,
                'cleanupCheckedAt': '2026-11-01T00:00:00Z', 'cleanupErrors': [],
            }))
            (root / 'pki').mkdir()
            (root / 'pki' / 'synthetic-key').write_text('synthetic-private-test-material')
            (root / 'overlap').mkdir()
            (evidence / 'proof').write_text('sanitized-test-evidence')
            blocked = subprocess.run([sys.executable, '-', str(root), str(root / 'overlap')],
                                     input=script, capture_output=True, text=True)
            self.assertNotEqual(0, blocked.returncode)
            self.assertTrue((root / 'pki' / 'synthetic-key').exists())
            result = subprocess.run([sys.executable, '-', str(root), str(evidence)],
                                    input=script, capture_output=True, text=True)
            self.assertEqual(0, result.returncode)
            self.assertTrue(json.loads(result.stdout)['privateStagingAbsent'])
            self.assertFalse(root.exists())
            self.assertEqual('sanitized-test-evidence', (evidence / 'proof').read_text())


if __name__ == '__main__':
    unittest.main()
