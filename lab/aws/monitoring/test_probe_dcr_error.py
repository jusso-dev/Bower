"""Offline tests: never contact Azure or read real credential files."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import urllib.error

spec = importlib.util.spec_from_file_location('probe_dcr_error', Path(__file__).with_name('probe-dcr-error.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.run = 'bower-val-261101030000-1234abcd'
        self.sub = '945092a0-2500-4b25-85a4-99f1c3135906'
        self.tenant = 'f4f33fb1-b681-40d1-a854-6f888d45b891'
        self.app = '11111111-1111-4111-8111-111111111111'
        self.obj = '22222222-2222-4222-8222-222222222222'
        self.sp = '33333333-3333-4333-8333-333333333333'
        self.immutable = 'dcr-' + 'a' * 32
        self.group = 'rg-' + self.run
        prefix = '/subscriptions/' + self.sub + '/resourceGroups/' + self.group + '/providers/Microsoft.Insights/'
        self.dcr = prefix + 'dataCollectionRules/' + self.run + '-dcr'
        self.dce = prefix + 'dataCollectionEndpoints/' + self.run + '-dce'
        self.endpoint = 'https://synthetic.ingest.monitor.azure.com'
        certificate = self.root / 'ingest-identity.pem'
        certificate.write_text('synthetic-not-a-real-key')
        certificate.chmod(0o600)
        self.state = {'run': self.run, 'group': self.group, 'workspaceName': self.run + '-logs',
                      'subscription': self.sub, 'tenant': self.tenant,
                      'workspaceResourceId': '/subscriptions/' + self.sub + '/resourceGroups/' + self.group
                      + '/providers/Microsoft.OperationalInsights/workspaces/' + self.run + '-logs',
                      'identities': {'ingest': {'name': self.run + '-ingest', 'appId': self.app,
                          'objectId': self.obj, 'principalId': self.sp, 'certificatePath': str(certificate)}},
                      'outputs': {'ingestPrincipalId': self.sp, 'dataCollectionEndpoint': self.endpoint,
                                  'dataCollectionRuleImmutableId': self.immutable, 'streamName': 'Custom-BowerSecurity'}}
        self.state_file = self.root / 'azure-state.json'
        self.write_state()
        self.env = types.SimpleNamespace(SUB=self.sub, TENANT=self.tenant, account=mock.Mock(),
            group_owned=mock.Mock(), exact_apps=mock.Mock(return_value=[{'id': self.obj, 'appId': self.app}]),
            principals=mock.Mock(return_value=[{'id': self.sp}]), az=mock.Mock(side_effect=self.azure_metadata))

    def write_state(self):
        self.state_file.write_text(json.dumps(self.state))
        self.state_file.chmod(0o600)

    def azure_metadata(self, *args):
        if args[:2] == ('resource', 'list'):
            return [{'id': self.dcr}]
        if args[:2] == ('rest', '--method'):
            url = args[args.index('--url') + 1]
            if self.dcr in url:
                return {'properties': {'immutableId': self.immutable,
                        'dataCollectionEndpointId': self.dce, 'streamDeclarations': {'Custom-BowerSecurity': {}}}}
            if self.dce in url:
                return {'properties': {'logsIngestion': {'endpoint': self.endpoint}}}
        raise AssertionError(args)

    def isolated(self, cache, *args):
        self.assertTrue(cache.is_dir())
        self.assertEqual(0o700, cache.stat().st_mode & 0o777)
        if args == ('account', 'show'):
            return {'tenantId': self.tenant, 'id': self.sub, 'user': {'type': 'servicePrincipal', 'name': self.app}}
        if args[:2] == ('account', 'get-access-token'):
            return {'accessToken': 'synthetic-token-do-not-print'}
        return None

    def test_target_checks_scoped_identity_and_endpoint(self):
        state, identity, cert, endpoint, immutable, stream = probe.owned_target(self.env, self.root)
        self.assertEqual((self.app, self.endpoint, self.immutable, 'Custom-BowerSecurity'),
                         (identity['appId'], endpoint, immutable, stream))
        self.env.group_owned.assert_called_once()
        self.assertEqual(self.root / 'ingest-identity.pem', cert)
        self.assertEqual(self.run, state['run'])

    def test_target_rejects_mismatched_scope_and_certificate(self):
        self.state['outputs']['ingestPrincipalId'] = self.obj
        self.write_state()
        with self.assertRaises(ValueError):
            probe.owned_target(self.env, self.root)
        self.state['outputs']['ingestPrincipalId'] = self.sp
        self.state['outputs']['dataCollectionEndpoint'] = 'https://other.example.test'
        self.write_state()
        with self.assertRaises(ValueError):
            probe.owned_target(self.env, self.root)
        self.state['outputs']['dataCollectionEndpoint'] = self.endpoint
        self.state['identities']['ingest']['certificatePath'] = str(self.root / 'different.pem')
        self.write_state()
        with self.assertRaises(ValueError):
            probe.owned_target(self.env, self.root)

    def test_target_rejects_dcr_linked_to_different_endpoint(self):
        def other_dce(*args):
            if args[:2] == ('rest', '--method') and self.dcr in args[args.index('--url') + 1]:
                return {'properties': {'immutableId': self.immutable, 'streamDeclarations': {'Custom-BowerSecurity': {}},
                                       'dataCollectionEndpointId': self.dce + '-foreign'}}
            return self.azure_metadata(*args)
        self.env.az.side_effect = other_dce
        with mock.patch.object(probe, 'isolated_az') as auth, self.assertRaises(ValueError):
            probe.probe(self.env, self.root)
        auth.assert_not_called()
        self.assertFalse(list(self.root.glob('dcr-probe-cli-*')))

    def test_one_accepted_request_is_not_diagnostic_success_and_cache_is_removed(self):
        response = mock.MagicMock()
        response.__enter__.return_value.status = 204
        opener = mock.Mock()
        opener.open.return_value = response
        output = io.StringIO()
        with mock.patch.object(probe, 'isolated_az', side_effect=self.isolated), \
             mock.patch.object(probe.urllib.request, 'build_opener', return_value=opener), \
             contextlib.redirect_stdout(output):
            result, path = probe.probe(self.env, self.root)
        self.assertEqual('accepted-for-processing', result['httpOutcome'])
        self.assertFalse(result['diagnosticQueryVerified'])
        self.assertFalse(result['deliveryQualified'])
        self.assertEqual((1, 31), (result['attempts'], result['payloadBytes']))
        self.assertEqual(1, opener.open.call_count)
        response.__enter__.return_value.read.assert_not_called()
        request = opener.open.call_args.args[0]
        self.assertEqual('POST', request.get_method())
        self.assertEqual(probe.PAYLOAD, request.data)
        self.assertEqual('application/json', request.get_header('Content-type'))
        self.assertTrue(request.full_url.startswith(self.endpoint + '/dataCollectionRules/'))
        self.assertNotIn('synthetic-token', path.read_text())
        self.assertNotIn('synthetic-token', output.getvalue())
        self.assertFalse(list(self.root.glob('dcr-probe-cli-*')))

    def test_400_is_rejected_without_reading_error_body_and_cache_removed(self):
        error = urllib.error.HTTPError('https://unused', 400, 'synthetic-secret', {}, io.BytesIO(b'secret-response'))
        opener = mock.Mock()
        opener.open.side_effect = error
        with mock.patch.object(probe, 'isolated_az', side_effect=self.isolated), \
             mock.patch.object(probe.urllib.request, 'build_opener', return_value=opener):
            result, path = probe.probe(self.env, self.root)
        self.assertEqual(('rejected', 400), (result['httpOutcome'], result['httpStatus']))
        self.assertFalse(result['diagnosticQueryVerified'])
        self.assertNotIn('secret-response', path.read_text())
        self.assertEqual(1, opener.open.call_count)
        self.assertFalse(list(self.root.glob('dcr-probe-cli-*')))

    def test_auth_failure_cleans_cache_without_exposing_output(self):
        with mock.patch.object(probe, 'isolated_az', side_effect=RuntimeError('synthetic-secret')):
            with self.assertRaises(RuntimeError):
                probe.probe(self.env, self.root)
        self.assertFalse(list(self.root.glob('dcr-probe-cli-*')))

    def test_network_timeout_records_unknown_without_retry_or_response_data(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.URLError('synthetic-secret')
        with mock.patch.object(probe, 'isolated_az', side_effect=self.isolated), \
             mock.patch.object(probe.urllib.request, 'build_opener', return_value=opener):
            result, path = probe.probe(self.env, self.root)
        self.assertEqual('other-or-unknown', result['httpOutcome'])
        self.assertIsNone(result['httpStatus'])
        self.assertFalse(result['diagnosticQueryVerified'])
        self.assertEqual(1, opener.open.call_count)
        self.assertNotIn('synthetic-secret', path.read_text())
        self.assertFalse(list(self.root.glob('dcr-probe-cli-*')))

    def test_redirects_are_not_followed(self):
        self.assertIsNone(probe.NoRedirect().redirect_request(None, None, 302, None, None, 'https://other.invalid'))

    def test_azure_cli_errors_never_expose_stderr(self):
        failure = types.SimpleNamespace(returncode=1, stderr='synthetic-secret', stdout='')
        with mock.patch.object(probe.subprocess, 'run', return_value=failure):
            with self.assertRaises(RuntimeError) as error:
                probe.isolated_az(self.root, 'login')
        self.assertNotIn('synthetic-secret', str(error.exception))

    def test_no_apply_rejects_before_network(self):
        result = subprocess.run([sys.executable, str(Path(probe.__file__)), '--state-dir', str(self.root)],
                                capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('requires --apply', result.stderr)
        self.assertFalse(list(self.root.glob('dcr-probe-cli-*')))


if __name__ == '__main__':
    unittest.main()
