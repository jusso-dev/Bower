#!/usr/bin/env python3
"""Submit exactly one malformed synthetic request to an owned DCR.

The HTTP status is not diagnostic verification. Query DCRLogErrors separately.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

PAYLOAD = b'{"bowerQualificationMalformed":'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_environment(repo):
    path = Path(repo) / 'lab/aws/monitoring/azure-environment.py'
    spec = importlib.util.spec_from_file_location('bower_lab_azure_environment', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def owned_target(env, root):
    state_file = root / 'azure-state.json'
    if state_file.is_symlink() or not state_file.is_file() or state_file.stat().st_mode & 0o077:
        raise ValueError('Private state file required')
    if state_file.stat().st_uid != os.getuid() or state_file.stat().st_size > 1024 * 1024:
        raise ValueError('Invalid state ownership or size')
    state = json.loads(state_file.read_text())
    run = state.get('run', '')
    if (state.get('subscription') != env.SUB or state.get('tenant') != env.TENANT
            or not re.fullmatch(r'bower-val-\d{12}-[0-9a-f]{8}', run)
            or state.get('group') != 'rg-' + run or state.get('workspaceName') != run + '-logs'):
        raise ValueError('Invalid owned target')
    expected_workspace = ('/subscriptions/' + env.SUB + '/resourceGroups/' + state['group']
                          + '/providers/Microsoft.OperationalInsights/workspaces/' + state['workspaceName'])
    if str(state.get('workspaceResourceId', '')).lower() != expected_workspace.lower():
        raise ValueError('Workspace ownership mismatch')
    env.account()
    env.group_owned(state)
    identity = state['identities']['ingest']
    uuid.UUID(identity['appId'])
    uuid.UUID(identity['objectId'])
    uuid.UUID(identity['principalId'])
    if identity['name'] != run + '-ingest':
        raise ValueError('Unexpected ingestion identity')
    apps = env.exact_apps(identity['name'])
    principals = env.principals(identity['appId'])
    if (len(apps) != 1 or apps[0]['id'] != identity['objectId'] or apps[0]['appId'] != identity['appId']
            or len(principals) != 1 or principals[0]['id'] != identity['principalId']):
        raise ValueError('Ingestion identity ownership mismatch')
    certificate = Path(identity['certificatePath'])
    if certificate.is_symlink() or certificate.resolve() != root / 'ingest-identity.pem':
        raise ValueError('Certificate path mismatch')
    info = certificate.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Certificate must be an owner-only regular file')
    values = {key: value['value'] if isinstance(value, dict) else value for key, value in state['outputs'].items()}
    if values.get('ingestPrincipalId', '').lower() != identity['principalId'].lower():
        raise ValueError('DCR ingestion principal mismatch')
    endpoint = values['dataCollectionEndpoint'].rstrip('/')
    parsed = urllib.parse.urlsplit(endpoint)
    if (parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith('.ingest.monitor.azure.com')
            or parsed.username or parsed.password or parsed.port or parsed.path or parsed.query or parsed.fragment):
        raise ValueError('Unexpected ingestion endpoint')
    immutable, stream = values['dataCollectionRuleImmutableId'], values['streamName']
    if not re.fullmatch(r'dcr-[0-9a-f]{32}', immutable) or stream != 'Custom-BowerSecurity':
        raise ValueError('Unexpected DCR identity or stream')
    prefix = ('/subscriptions/' + env.SUB + '/resourceGroups/' + state['group']
              + '/providers/Microsoft.Insights/').lower()
    rules = env.az('resource', 'list', '--subscription', env.SUB, '--resource-group', state['group'],
                   '--resource-type', 'Microsoft.Insights/dataCollectionRules') or []
    if len(rules) != 1 or rules[0]['id'].lower() != prefix + 'datacollectionrules/' + run + '-dcr':
        raise ValueError('Ambiguous or unowned DCR')
    rule = env.az('rest', '--method', 'get', '--url',
                  'https://management.azure.com' + rules[0]['id'] + '?api-version=2023-03-11')
    if rule['properties']['immutableId'] != immutable or stream not in rule['properties']['streamDeclarations']:
        raise ValueError('DCR identity mismatch')
    dce_id = rule['properties']['dataCollectionEndpointId']
    if dce_id.lower() != prefix + 'datacollectionendpoints/' + run + '-dce':
        raise ValueError('DCR endpoint ownership mismatch')
    dce = env.az('rest', '--method', 'get', '--url',
                 'https://management.azure.com' + dce_id + '?api-version=2024-03-11')
    if dce['properties']['logsIngestion']['endpoint'].rstrip('/').lower() != endpoint.lower():
        raise ValueError('Endpoint does not match owned DCR')
    return state, identity, certificate, endpoint, immutable, stream


def isolated_az(cache, *args):
    process_env = {**os.environ, 'AZURE_CONFIG_DIR': str(cache), 'AZURE_CORE_COLLECT_TELEMETRY': 'no'}
    result = subprocess.run(['az', *args, '--output', 'json', '--only-show-errors'], env=process_env,
                            capture_output=True, text=True, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError('Isolated Azure CLI operation failed')
    return json.loads(result.stdout) if result.stdout.strip() else None


def probe(env, root):
    state, identity, certificate, endpoint, immutable, stream = owned_target(env, root)
    cache = Path(tempfile.mkdtemp(prefix='dcr-probe-cli-', dir=root))
    os.chmod(cache, 0o700)
    try:
        isolated_az(cache, 'login', '--service-principal', '--username', identity['appId'],
                    '--certificate', str(certificate), '--tenant', env.TENANT)
        isolated_az(cache, 'account', 'set', '--subscription', env.SUB)
        account = isolated_az(cache, 'account', 'show')
        if (account['tenantId'] != env.TENANT or account['id'] != env.SUB
                or account['user']['type'].lower() != 'serviceprincipal'
                or account['user']['name'].lower() != identity['appId'].lower()):
            raise ValueError('Authenticated ingestion identity mismatch')
        token = isolated_az(cache, 'account', 'get-access-token', '--resource', 'https://monitor.azure.com/')['accessToken']
        request_id = str(uuid.uuid4())
        url = endpoint + '/dataCollectionRules/' + immutable + '/streams/' + stream + '?api-version=2023-01-01'
        request = urllib.request.Request(url, data=PAYLOAD, method='POST', headers={
            'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'x-ms-client-request-id': request_id})
        del token
        started = dt.datetime.now(dt.timezone.utc).isoformat()
        status, transport_error = None, None
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(request, timeout=60) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            transport_error = type(error).__name__
        result = {'recordType': 'owned-dcr-malformed-request-probe', 'runId': state['run'],
                  'startedAt': started, 'finishedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'requestId': request_id, 'httpStatus': status,
                  'httpOutcome': 'accepted-for-processing' if status == 204 else 'rejected' if status == 400 else 'other-or-unknown',
                  'payloadSha256': hashlib.sha256(PAYLOAD).hexdigest(), 'payloadBytes': len(PAYLOAD),
                  'transportErrorCategory': transport_error, 'diagnosticQueryVerified': False,
                  'deliveryQualified': False, 'attempts': 1}
        path = root / ('dcr-malformed-probe-' + request_id + '.json')
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(result, output, indent=2)
            output.write('\n')
        return result, path
    finally:
        shutil.rmtree(cache)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', required=True, type=Path)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--apply', action='store_true', help='send one synthetic malformed request')
    args = parser.parse_args()
    if not args.apply:
        parser.error('sending a request requires --apply')
    os.umask(0o077)
    try:
        env = load_environment(args.repo)
        root = env.secure_dir(args.state_dir)
        result, path = probe(env, root)
        print(json.dumps({'evidence': str(path), 'httpStatus': result['httpStatus'],
                          'httpOutcome': result['httpOutcome'], 'diagnosticQueryVerified': False}))
        return 0 if result['httpStatus'] in (204, 400) else 1
    except Exception as error:
        # No exception message, HTTP response, token, certificate, or CLI output may escape.
        print(json.dumps({'status': 'failed', 'category': type(error).__name__, 'diagnosticQueryVerified': False}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
