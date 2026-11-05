"""Reconciliation readers must not accept a cached empty destination result."""
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def response(fresh):
    return {'tables': [{'columns': [{'name': 'EventId'}], 'rows': [['fresh']] if fresh else []}]}


class Reply:
    status = 200
    headers = {}

    def __init__(self, request):
        self.body = json.dumps(response(request.get_header('Cache-control') == 'no-cache')).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.body


class QueryCacheTests(unittest.TestCase):
    def test_storage_verifier_bypasses_cached_empty_response(self):
        module = load('storage_query_cache', ROOT / 'scripts' / 'storage-query.py')
        with mock.patch.object(module.urllib.request, 'urlopen', side_effect=lambda request, **_: Reply(request)):
            rows = module.query('workspace', 'synthetic-token', 'T | take 1')
        self.assertEqual([{'EventId': 'fresh'}], rows)

    def test_soak_verifier_bypasses_cached_empty_response(self):
        module = load('soak_query_cache', ROOT / 'soak' / 'reconcile.py')
        verifier = object.__new__(module.Verifier)
        verifier.state = {'workspaceId': 'workspace'}
        verifier.az = lambda *args: {'accessToken': 'synthetic-token'}
        opener = types.SimpleNamespace(open=lambda request, **_: Reply(request))
        with mock.patch.object(module.urllib.request, 'build_opener', return_value=opener):
            rows, _ = verifier.query('T | take 1')
        self.assertEqual([{'EventId': 'fresh'}], rows)

    def test_azure_qualification_bypasses_cached_empty_response(self):
        module = load('azure_qualification_cache', ROOT / 'monitoring' / 'qualify-azure.py')
        with mock.patch.object(module, 'az', side_effect=lambda *args: response('Cache-Control=no-cache' in args)):
            rows = module.query({'workspaceId': 'workspace'}, 'T | take 1')
        self.assertEqual([{'EventId': 'fresh'}], rows)

    def test_sentinel_validation_bypasses_cached_empty_response(self):
        module = load('sentinel_validation_cache', REPO / 'deploy' / 'sentinel' / 'analytics' / 'validation' / 'verify.py')
        def run(args, **kwargs):
            return types.SimpleNamespace(stdout=json.dumps(response('Cache-Control=no-cache' in args)))
        with mock.patch.object(module.subprocess, 'run', side_effect=run):
            rows = module.query('workspace', 'T | take 1')
        self.assertEqual([{'EventId': 'fresh'}], rows)

    def test_sentinel_validation_does_not_echo_partial_error_content(self):
        module = load('sentinel_validation_partial', REPO / 'deploy' / 'sentinel' / 'analytics' / 'validation' / 'verify.py')
        partial = {'error': {'code': 'PartialError', 'message': 'sensitive-query-marker'},
                   'tables': [{'columns': [{'name': 'EventId'}], 'rows': [['e1']]}]}
        with mock.patch.object(module, 'az_rest', return_value=partial), self.assertRaises(SystemExit) as caught:
            module.query('workspace', 'T | take 1')
        self.assertIn('partial results', str(caught.exception))
        self.assertNotIn('sensitive-query-marker', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
