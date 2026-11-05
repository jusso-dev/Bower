#!/usr/bin/env python3
"""Disposable, run-owned Azure destination for the Bower pilot.

All mutating commands require --apply. State and private credentials stay in an
owner-only directory; Azure CLI errors are reduced to operation names.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid

SUB = '945092a0-2500-4b25-85a4-99f1c3135906'
TENANT = 'f4f33fb1-b681-40d1-a854-6f888d45b891'
REGION = 'australiaeast'
PROJECT = 'bower-lab'
READER_ROLE = '73c42c96-874c-492b-b04d-ab87d138a893'
ROLES = ('ingest', 'verifier')
# Local credential files per role; 'ingest-next' is the overlap certificate of a rotation.
CREDENTIAL_FILES = ('ingest', 'verifier', 'ingest-next')
GRAPH_DELETED = 'https://graph.microsoft.com/v1.0/directory/deletedItems/'
# A generated name, or the owning AWS run's id so Azure resources share its RunId.
RUN_PATTERN = r'bower-val-\d{12}-[0-9a-f]{8}|bower-(?:ws6|fw|soak|resoak)-\d{8}-\d{6}'


class NotFoundError(RuntimeError):
    """Graph or Resource Manager reported the object as not found (only that proves absence)."""


def az(*args):
    result = subprocess.run(['az', *args, '--only-show-errors', '--output', 'json'],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        # Azure errors can echo input; never print error text or tokens. Only the exact
        # not-found codes are classified; everything else stays a generic failure.
        if re.search(r'\b(Request_ResourceNotFound|ResourceNotFound|ResourceGroupNotFound)\b', result.stderr):
            raise NotFoundError('Azure object not found: ' + ' '.join(args[:2]))
        raise RuntimeError('Azure CLI failed: ' + ' '.join(args[:2]))
    return json.loads(result.stdout) if result.stdout.strip() else None


def secure_dir(path):
    path = Path(path).expanduser()
    if path.is_symlink():
        raise ValueError('State directory cannot be a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = path.resolve(strict=True)
    azure_dir = (Path.home() / '.azure').resolve()
    if path == azure_dir or azure_dir in path.parents:
        raise ValueError('State must not be inside the default Azure CLI directory')
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('State directory must be owned by the user and mode 0700')
    return path


def atomic_json(path, data):
    fd, name = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(data, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def account():
    target = az('account', 'show', '--subscription', SUB)
    current = az('account', 'show')
    if target['id'].lower() != SUB or target['tenantId'].lower() != TENANT or current['tenantId'].lower() != TENANT:
        raise RuntimeError('Azure subscription or tenant mismatch')


def exact_apps(name):
    return [item for item in (az('ad', 'app', 'list', '--display-name', name) or [])
            if item.get('displayName') == name]


def principals(app_id):
    uuid.UUID(app_id)
    return [item for item in (az('ad', 'sp', 'list', '--filter', "appId eq '" + app_id + "'") or [])
            if item.get('appId') == app_id]


def group_owned(state):
    group = az('group', 'show', '--name', state['group'], '--subscription', SUB)
    tags = group.get('tags') or {}
    if tags.get('Project') != PROJECT or tags.get('RunId') != state['run']:
        raise RuntimeError('Resource group ownership tags do not match')


def owned_assignments(state, principal_id):
    uuid.UUID(principal_id)
    prefix = ('/subscriptions/' + SUB + '/resourcegroups/' + state['group']).lower()
    grants = az('role', 'assignment', 'list', '--all', '--assignee-object-id', principal_id,
                '--subscription', SUB) or []
    return [grant for grant in grants if grant.get('scope', '').lower() == prefix
            or grant.get('scope', '').lower().startswith(prefix + '/')]


def parameters(state):
    return ['workspaceName=' + state['workspaceName'], 'namePrefix=' + state['run'],
            'location=' + REGION, 'ingestPrincipalObjectId=' + state['identities']['ingest']['principalId']]


def plan_hash(repo, state):
    digest = hashlib.sha256()
    for name in ('main.bicep', 'private-endpoint.bicep'):
        digest.update((repo / 'deploy' / 'bicep' / name).read_bytes())
    digest.update(json.dumps(parameters(state), sort_keys=True).encode())
    return digest.hexdigest()


def new_certificate(root, name, subject, days):
    key, cert, pem = [root / (name + suffix) for suffix in ('-key.pem', '-cert.pem', '-identity.pem')]
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(key),
                    '-out', str(cert), '-days', str(days), '-subj', '/CN=' + subject],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    pem.write_bytes(key.read_bytes() + cert.read_bytes())
    for path in (key, cert, pem):
        path.chmod(0o600)
    return cert, pem


def add_ingest_credential(root, state_path, state):
    """Rotation with overlap (guide 05, section 6.1.2): append a second certificate to the ingestion
    application. Both stay valid; the collectors switch to the new one later."""
    identity = state['identities']['ingest']
    if identity.get('nextCertificatePath'):
        raise RuntimeError('A second ingestion credential already exists')
    days = state.get('credentialDays', 2)
    cert, pem = new_certificate(root, 'ingest-next', identity['name'] + '-next', days)
    identity['nextCertificatePath'] = str(pem)
    atomic_json(state_path, state)
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    az('ad', 'app', 'credential', 'reset', '--id', identity['appId'], '--append', '--cert', '@' + str(cert), '--end-date', expiry)
    identity['nextCredentialExpiresAt'] = expiry
    atomic_json(state_path, state)
    return {'added': True, 'expiresAt': expiry}


def prepare(root, state_path, run_id=None, credential_days=2, expires_hours=12):
    if state_path.exists():
        raise RuntimeError('State already exists; use cleanup or another state directory')
    now = dt.datetime.now(dt.timezone.utc)
    run = run_id or 'bower-val-' + now.strftime('%y%m%d%H%M%S') + '-' + secrets.token_hex(4)
    if not re.fullmatch(RUN_PATTERN, run):
        raise ValueError('Invalid Azure run id')
    state = {'run': run, 'group': 'rg-' + run, 'workspaceName': run + '-logs',
             'subscription': SUB, 'tenant': TENANT, 'region': REGION,
             'createdAt': now.isoformat(), 'identities': {}, 'credentialDays': credential_days}
    if az('group', 'exists', '--name', state['group'], '--subscription', SUB):
        raise RuntimeError('Generated resource group already exists')
    for role in ROLES:
        name = run + '-' + role
        if exact_apps(name):
            raise RuntimeError('Generated application name already exists')
        state['identities'][role] = {'name': name, 'nameChecked': True}
    atomic_json(state_path, state)
    expires = (now + dt.timedelta(hours=expires_hours)).isoformat()
    group_url = ('https://management.azure.com/subscriptions/' + SUB + '/resourcegroups/'
                 + state['group'] + '?api-version=2021-04-01')
    az('rest', '--method', 'put', '--url', group_url, '--headers', 'If-None-Match=*',
       '--body', json.dumps({'location': REGION, 'tags': {'Project': PROJECT, 'RunId': run, 'ExpiresAt': expires}}))
    group_owned(state)
    workspace = az('monitor', 'log-analytics', 'workspace', 'create', '--resource-group', state['group'],
                   '--workspace-name', state['workspaceName'], '--location', REGION, '--sku', 'PerGB2018',
                   '--retention-time', '30', '--subscription', SUB,
                   '--tags', 'Project=' + PROJECT, 'RunId=' + run, 'ExpiresAt=' + expires)
    state['workspaceId'], state['workspaceResourceId'] = workspace['customerId'], workspace['id']
    atomic_json(state_path, state)
    for role in ROLES:
        identity = state['identities'][role]
        identity['creationAttempted'] = True
        atomic_json(state_path, state)
        app = az('ad', 'app', 'create', '--display-name', identity['name'], '--sign-in-audience', 'AzureADMyOrg')
        identity.update(appId=app['appId'], objectId=app['id'])
        atomic_json(state_path, state)
        principal = az('ad', 'sp', 'create', '--id', app['appId'])
        identity['principalId'] = principal['id']
        atomic_json(state_path, state)
        cert, pem = new_certificate(root, role, identity['name'], credential_days)
        identity['certificatePath'] = str(pem)
        atomic_json(state_path, state)
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=credential_days)).strftime('%Y-%m-%dT%H:%M:%SZ')
        az('ad', 'app', 'credential', 'reset', '--id', app['appId'], '--append', '--cert', '@' + str(cert), '--end-date', expiry)
        identity['credentialExpiresAt'] = expiry
        atomic_json(state_path, state)
    grant = az('role', 'assignment', 'create', '--assignee-object-id', state['identities']['verifier']['principalId'],
               '--assignee-principal-type', 'ServicePrincipal', '--role', READER_ROLE,
               '--scope', state['workspaceResourceId'], '--subscription', SUB)
    state['verifierRoleAssignmentId'] = grant['id']
    atomic_json(state_path, state)
    return state


def local_cleanup(root):
    failures = []
    for role in CREDENTIAL_FILES:
        for suffix in ('-key.pem', '-cert.pem', '-identity.pem'):
            try:
                (root / (role + suffix)).unlink(missing_ok=True)
            except OSError:
                failures.append(role + suffix)
        if role not in ROLES:
            continue
        cache = root / ('azure-cli-' + role)
        try:
            if cache.is_symlink():
                cache.unlink()
            elif cache.exists():
                shutil.rmtree(cache)
        except OSError:
            failures.append(cache.name)
    return failures


def purge_deleted(object_id):
    """Permanently remove a soft-deleted application or service principal. True only when Graph
    then reports it not found; any other failure (throttling, permission, token) is unverified."""
    uuid.UUID(object_id)
    try:
        az('rest', '--method', 'delete', '--url', GRAPH_DELETED + object_id)
    except RuntimeError:
        pass
    try:
        az('rest', '--method', 'get', '--url', GRAPH_DELETED + object_id)
        return False
    except NotFoundError:
        return True
    except RuntimeError:
        return False


def cleanup(root, state_path, state, timeout):
    errors = []
    # Reconcile names recorded before app creation. Only exact, unique run-owned names qualify.
    for role in ROLES:
        identity = state.get('identities', {}).get(role)
        if not identity:
            continue
        try:
            if identity.get('name') != state['run'] + '-' + role or not identity.get('nameChecked'):
                raise RuntimeError('Identity ownership record invalid')
            matches = exact_apps(identity['name'])
            if len(matches) > 1:
                raise RuntimeError('Application name is ambiguous')
            if not matches and identity.get('creationAttempted') and not identity.get('appId'):
                raise RuntimeError('Cannot verify an interrupted application creation')
            if matches:
                if not identity.get('appId') and identity.get('creationAttempted') is not True:
                    raise RuntimeError('Application creation was never attempted for this run')
                app = matches[0]
                if identity.get('appId') and (app['appId'] != identity['appId'] or app['id'] != identity['objectId']):
                    raise RuntimeError('Application identity mismatch')
                identity.update(appId=app['appId'], objectId=app['id'])
                atomic_json(state_path, state)
            app_id = identity.get('appId')
            if app_id:
                sps = principals(app_id)
                if len(sps) > 1 or (identity.get('principalId') and sps and sps[0]['id'] != identity['principalId']):
                    raise RuntimeError('Service principal identity mismatch')
                for sp in sps:
                    identity['principalId'] = sp['id']
                    atomic_json(state_path, state)
                if identity.get('principalId'):
                    for grant in owned_assignments(state, identity['principalId']):
                        az('role', 'assignment', 'delete', '--ids', grant['id'], '--subscription', SUB)
                for sp in sps:
                    az('ad', 'sp', 'delete', '--id', sp['id'])
                if matches:
                    az('ad', 'app', 'delete', '--id', app['id'])
                # Deleted applications and principals stay restorable for 30 days unless purged.
                for object_id in (identity.get('objectId'), identity.get('principalId')):
                    if object_id:
                        purge_deleted(object_id)
        except Exception:
            errors.append(role + ' cleanup failed; rerun cleanup and inspect ownership')
    try:
        if az('group', 'exists', '--name', state['group'], '--subscription', SUB):
            group_owned(state)
            # Force-delete the workspace first so it is not kept soft-deleted for 14 days.
            if state.get('workspaceResourceId'):
                try:
                    az('monitor', 'log-analytics', 'workspace', 'delete', '--resource-group', state['group'],
                       '--workspace-name', state['workspaceName'], '--subscription', SUB, '--force', 'true', '--yes')
                except RuntimeError:
                    errors.append('workspace force delete failed')
            az('group', 'delete', '--name', state['group'], '--subscription', SUB, '--yes', '--no-wait')
    except Exception:
        errors.append('resource group cleanup failed or ownership mismatch')
    errors.extend(local_cleanup(root))
    deadline = time.monotonic() + timeout
    while True:
        try:
            remaining = []
            if az('group', 'exists', '--name', state['group'], '--subscription', SUB):
                remaining.append('resource group')
            for role in ROLES:
                identity = state.get('identities', {}).get(role, {})
                if identity.get('name') and exact_apps(identity['name']):
                    remaining.append(role + ' application')
                if identity.get('appId') and principals(identity['appId']):
                    remaining.append(role + ' service principal')
                if identity.get('principalId') and owned_assignments(state, identity['principalId']):
                    remaining.append(role + ' role assignment')
                for kind, object_id in (('application', identity.get('objectId')), ('service principal', identity.get('principalId'))):
                    if object_id and not purge_deleted(object_id):
                        remaining.append(role + ' deleted ' + kind + ' (present or purge unverified)')
            if not remaining or time.monotonic() >= deadline:
                errors.extend('remaining: ' + item for item in remaining)
                break
            time.sleep(2)
        except Exception:
            errors.append('cleanup verification failed')
            break
    state['cleanupCheckedAt'] = dt.datetime.now(dt.timezone.utc).isoformat()
    state['cleanupErrors'] = errors
    atomic_json(state_path, state)
    if errors:
        raise RuntimeError('; '.join(errors))
    return {'cleaned': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'plan', 'apply', 'sentinel', 'status', 'cleanup', 'add-ingest-credential'])
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--apply', action='store_true', help='explicitly authorize this action to modify Azure')
    parser.add_argument('--timeout-seconds', type=int, default=300)
    parser.add_argument('--run-id', help='prepare only: name Azure resources after this owning AWS RunId')
    parser.add_argument('--credential-days', type=int, default=2,
                        help='prepare only: certificate credential lifetime (1-7 days; the 72-hour re-soak needs 7)')
    parser.add_argument('--expires-hours', type=int, default=12,
                        help='prepare only: the ExpiresAt metadata tag (1-200 hours; the re-soak sets its guard time)')
    args = parser.parse_args()
    if args.action in ('prepare', 'apply', 'sentinel', 'cleanup', 'add-ingest-credential') and not args.apply:
        parser.error('this action requires --apply')
    if args.timeout_seconds < 0:
        parser.error('timeout must be non-negative')
    if not 1 <= args.credential_days <= 7:
        parser.error('credential days must be 1 to 7')
    if not 1 <= args.expires_hours <= 200:
        parser.error('expires hours must be 1 to 200')
    os.umask(0o077)
    root = secure_dir(args.state_dir)
    state_path = root / 'azure-state.json'
    owns_local_files = False
    try:
        if args.action == 'prepare':
            reserved = [state_path, root / 'azure-what-if.json']
            for role in CREDENTIAL_FILES:
                reserved.extend(root / (role + suffix) for suffix in ('-key.pem', '-cert.pem', '-identity.pem'))
            reserved.extend(root / ('azure-cli-' + role) for role in ROLES)
            if any(os.path.lexists(path) for path in reserved):
                raise RuntimeError('State directory contains existing lab files; use a fresh directory')
            owns_local_files = True
            account()
            state = prepare(root, state_path, args.run_id, args.credential_days, args.expires_hours)
            result = {'prepared': True, 'group': state['group'], 'workspaceId': state['workspaceId']}
        else:
            state = json.loads(state_path.read_text())
            if state.get('subscription') != SUB or state.get('tenant') != TENANT or not re.fullmatch(RUN_PATTERN, state.get('run', '')) or state.get('group') != 'rg-' + state['run'] or state.get('workspaceName') != state['run'] + '-logs':
                raise RuntimeError('Invalid saved deployment target or run')
            workspace = ('/subscriptions/' + SUB + '/resourceGroups/' + state['group']
                         + '/providers/Microsoft.OperationalInsights/workspaces/' + state['workspaceName'])
            if state.get('workspaceResourceId') and state['workspaceResourceId'].lower() != workspace.lower():
                raise RuntimeError('Invalid saved workspace ownership')
            owns_local_files = True
            account()
            if args.action in ('plan', 'apply', 'sentinel', 'add-ingest-credential'):
                group_owned(state)
            if args.action == 'plan':
                plan = az('deployment', 'group', 'what-if', '--name', state['run'] + '-destination', '--resource-group', state['group'], '--subscription', SUB, '--template-file', str(args.repo / 'deploy/bicep/main.bicep'), '--parameters', *parameters(state), '--no-pretty-print')
                atomic_json(root / 'azure-what-if.json', plan)
                state['deploymentPlanHash'] = plan_hash(args.repo, state)
                atomic_json(state_path, state)
                result = {'status': plan.get('status'), 'changes': [{'type': item['changeType'], 'resourceId': item['resourceId']} for item in plan.get('changes', [])]}
            elif args.action == 'apply':
                if plan_hash(args.repo, state) != state.get('deploymentPlanHash'):
                    raise RuntimeError('Deployment inputs changed after plan')
                deployment = az('deployment', 'group', 'create', '--name', state['run'] + '-destination', '--resource-group', state['group'], '--subscription', SUB, '--template-file', str(args.repo / 'deploy/bicep/main.bicep'), '--parameters', *parameters(state))
                state['outputs'] = {key: value['value'] for key, value in deployment['properties']['outputs'].items()}
                atomic_json(state_path, state)
                result = {'deploymentState': deployment['properties']['provisioningState'], 'outputs': state['outputs']}
            elif args.action == 'sentinel':
                url = 'https://management.azure.com' + state['workspaceResourceId'] + '/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01'
                response = az('rest', '--method', 'put', '--url', url, '--body', json.dumps({'properties': {'customerManagedKey': False}}))
                state['sentinelResourceId'] = response['id']
                atomic_json(state_path, state)
                result = {'sentinelResourceId': response['id']}
            elif args.action == 'cleanup':
                result = cleanup(root, state_path, state, args.timeout_seconds)
            elif args.action == 'add-ingest-credential':
                result = add_ingest_credential(root, state_path, state)
            else:
                result = {key: value for key, value in state.items() if key != 'identities'}
        print(json.dumps(result))
    except Exception as exc:
        # A read-only or retryable deployment/authentication failure must not
        # destroy the credentials needed to finish an active campaign.
        local_errors = local_cleanup(root) if owns_local_files and args.action in ('prepare', 'cleanup') else []
        # This exception is restricted to our own generic errors, never Azure stderr.
        print('Azure lab error: ' + str(exc) if isinstance(exc, (ValueError, RuntimeError)) else 'Azure lab error; inspect state and rerun cleanup', file=__import__('sys').stderr)
        if local_errors:
            print('Local credential cleanup incomplete; inspect the protected state directory', file=__import__('sys').stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
