#!/usr/bin/env python3
"""Disposable live Azure KQL qualification using synthetic, explicitly labelled rows.

This tests actual ingestion/query semantics, not collector delivery. Azure CLI owns
authentication; no tokens are read or persisted here. Cleanup runs even on failure.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parents[3]
SUB = '945092a0-2500-4b25-85a4-99f1c3135906'
TENANT = 'f4f33fb1-b681-40d1-a854-6f888d45b891'
API = 'https://management.azure.com'


def az(*args):
    result = subprocess.run(['az', *args, '--only-show-errors', '-o', 'json'],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        # Azure errors can echo input; never include the error body in evidence.
        codes = re.findall(r'ERROR: \(([A-Za-z0-9_.-]+)\)', result.stderr)
        operation = ' '.join(args[:2])
        print('Azure CLI failure: ' + operation + ' codes=' + ','.join(codes), flush=True)
        raise RuntimeError('Azure CLI command failed: ' + operation)
    return json.loads(result.stdout) if result.stdout.strip() else None


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def verify_account():
    account = az('account', 'show', '--subscription', SUB)
    current = az('account', 'show')
    if account['id'] != SUB or account['tenantId'] != TENANT or current['tenantId'] != TENANT:
        raise RuntimeError('Unexpected Azure account')


def create_owned_group(state, evidence):
    if az('group', 'exists', '--name', state['group'], '--subscription', SUB):
        raise RuntimeError('Generated resource group already exists; refusing to adopt it')
    # Persist the attempt before the conditional create so a lost response can
    # still be reconciled by exact run tags, without adopting a name collision.
    state['groupCreationAttempted'] = True
    save(evidence / 'state.json', state)
    url = API + '/subscriptions/' + SUB + '/resourcegroups/' + state['group'] + '?api-version=2021-04-01'
    az('rest', '--method', 'put', '--url', url, '--headers', 'If-None-Match=*',
       '--body', json.dumps({'location': 'australiaeast', 'tags': {'Project': 'bower-lab', 'RunId': state['runId']}}))
    group = az('group', 'show', '--name', state['group'], '--subscription', SUB)
    tags = group.get('tags') or {}
    if tags.get('Project') != 'bower-lab' or tags.get('RunId') != state['runId']:
        raise RuntimeError('Created resource group ownership mismatch')


def rest(method, url, body=None, resource=None):
    args = ['rest', '--method', method, '--url', url]
    if resource:
        args += ['--resource', resource]
    if body is None:
        return az(*args)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as handle:
        json.dump(body, handle)
        handle.flush()
        return az(*args, '--headers', 'Content-Type=application/json', '--body', '@' + handle.name)


def query(state, kql):
    result = rest('post', 'https://api.loganalytics.azure.com/v1/workspaces/' + state['workspaceId'] + '/query',
                  {'query': kql, 'timespan': 'P2D'}, 'https://api.loganalytics.io')
    if result.get('error'):
        raise RuntimeError('Log Analytics returned an error or partial result')
    table = result['tables'][0]
    return [dict(zip((c['name'] for c in table['columns']), row)) for row in table['rows']]


def rule(state, name):
    source = (REPO / 'deploy/sentinel/monitoring/queries' / (name + '.kql')).read_text()
    replacements = {
        '__DCR_RESOURCE_ID__': state['dcrId'].lower(), '__MISSING_MINUTES__': '15',
        '__EXPECTED_COLLECTORS__': '["qualification-never"]', '__NO_INGESTION_MINUTES__': '5',
        '__STORAGE_PERCENT__': '40', '__PAGES_PERCENT__': '70', '__BACKLOG_SECONDS__': '900',
        '__LAG_MINUTES__': '15', '__SILENCE_MINUTES__': '5', '__SILENCE_OVERRIDES__': '[]',
        '__SYSLOG_CHURN__': '5', '__CERTIFICATE_DAYS__': '14', '__CRL_HOURS__': '24',
    }
    for key, value in replacements.items():
        source = source.replace(key, value)
    if re.search(r'__[A-Z_]+__', source):
        raise RuntimeError('Unresolved KQL parameter')
    rows = query(state, source)
    if '_evidence' in state:
        observations = state.setdefault('_observations', [])
        observations.append({'query': name, 'queriedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                             'sourceSha256': hashlib.sha256(source.encode()).hexdigest(), 'rows': rows})
        save(state['_evidence'] / 'query-observations.json', observations)
    return rows


def record(collector, event_type, attributes, age_minutes=0):
    stamp = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=age_minutes)).isoformat()
    # Use the ingestion stream's envelope schema, not destination table column names.
    return {'schemaVersion': '1.0.0', 'timeGenerated': stamp, 'timeObserved': stamp,
            'eventId': str(uuid.uuid4()), 'eventType': event_type,
            'eventCategory': 'collector-health' if event_type == 'collector_health' else 'authentication',
            'eventAction': 'qualification', 'eventResult': 'success', 'eventSeverity': 'informational',
            'collector': {'id': collector},
            'application': {'name': 'synthetic-kql-qualification', 'environment': 'lab'},
            'labels': {'qualification': 'synthetic-direct-ingestion'}, 'attributes': attributes}


def ingest(state, rows):
    url = state['endpoint'].rstrip('/') + '/dataCollectionRules/' + state['immutableId']
    url += '/streams/Custom-BowerSecurity?api-version=2023-01-01'
    return rest('post', url, rows, 'https://monitor.azure.com')


def wait_rows(state, count):
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        rows = query(state, 'BowerSecurity_CL | summarize by EventId | summarize Count=count()')
        if rows[0]['Count'] >= count:
            return
        time.sleep(15)
    raise RuntimeError('Synthetic ingestion not query-visible within thirty minutes')


def qualify(state, evidence):
    state['_evidence'] = evidence
    print('Checking empty-workspace queries', flush=True)
    results = {}
    results['emptyTableSilence'] = rule(state, 'table-no-ingestion')
    results['absentDiagnosticTables'] = rule(state, 'dcr-errors')
    assert len(results['emptyTableSilence']) == 1
    assert not results['absentDiagnosticTables']
    save(evidence / 'query-results.json', results)
    # This row is outside a five-minute event-time window, but has just been ingested.
    late_row = record('qualification-late', 'authentication_failure', {}, 60)
    for attempt in range(20):
        try:
            ingest(state, [late_row])
            break
        except RuntimeError:
            if attempt == 19:
                raise
            time.sleep(15)  # Allow the new DCR-scoped role assignment to propagate.
    wait_rows(state, 1)
    results['lateArrivalSilence'] = rule(state, 'table-no-ingestion')
    results['lateArrivalFreshness'] = rule(state, 'destination-freshness')
    assert not results['lateArrivalSilence']
    assert not results['lateArrivalFreshness']
    print('Late-arrival queries passed; checking health fixtures', flush=True)
    healthy = {'storage': {'capacityUsedPercent': 0, 'queuePagesUsedPercent': 1},
               'queue': {'undelivered': 0, 'oldestUndeliveredAgeSeconds': 0, 'deadLettered': 0},
               'delivery': {'status': 'healthy'}, 'intake': {'capacityRefusals': 0},
               'sources': {'overdue': []}, 'syslog': [], 'windowsEventLog': [],
               'monitoringCoverage': {'syslogComplete': True, 'windowsEventLogComplete': True}}
    pressure = json.loads(json.dumps(healthy))
    pressure['storage']['queuePagesUsedPercent'] = 95
    pressure['queue'].update(undelivered=12, oldestUndeliveredAgeSeconds=1800, deadLettered=2)
    pressure['sources']['overdue'] = [{'application': 'fixture', 'environment': 'lab', 'state': 'overdue',
                                      'silentSeconds': 1200, 'allowedSilenceSeconds': 300}]
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=12)).isoformat()
    far_expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).isoformat()
    pressure['syslog'] = [{'id': 'a13', 'protocol': 'tls', 'tlsHandshakeFailures': 2, 'connectionsAccepted': 1,
                          'serverCertificateNotAfter': expiry, 'clientCertificateAuthorityNotAfter': far_expiry,
                          'clientRevocationListNextUpdate': far_expiry},
                         # No revocation list configured: its missing date is not applicable.
                         {'id': 'relp-no-crl', 'protocol': 'relp', 'tls': True,
                          'serverCertificateNotAfter': far_expiry, 'clientCertificateAuthorityNotAfter': far_expiry,
                          'clientCertificateAuthorityConfigured': True, 'clientRevocationListConfigured': False},
                         # Older collector without the flags: a missing date stays unknown.
                         {'id': 'legacy-no-flags', 'protocol': 'relp', 'tls': True,
                          'serverCertificateNotAfter': far_expiry, 'clientCertificateAuthorityNotAfter': far_expiry},
                         # Configured revocation list without a date: unknown.
                         {'id': 'crl-missing', 'protocol': 'tls', 'tls': True,
                          'serverCertificateNotAfter': far_expiry, 'clientCertificateAuthorityNotAfter': far_expiry,
                          'clientCertificateAuthorityConfigured': True, 'clientRevocationListConfigured': True}]
    pressure['windowsEventLog'] = [{'id': 'wec', 'state': 'failed', 'readErrors': 1}]
    pressure['problems'] = ['destination-credential']
    pressure['delivery']['lastFailureCode'] = 'destination-azure-http-403'
    ingest(state, [record('qualification-healthy', 'collector_health', healthy),
                   record('qualification-pressure', 'collector_health', pressure)])
    wait_rows(state, 3)
    for name in ('queue-storage', 'queue-backlog', 'dead-letters', 'source-overdue'):
        results[name] = rule(state, name)
        assert {r['CollectorId'] for r in results[name]} == {'qualification-pressure'}, name
    results['collector-health-missing'] = rule(state, 'collector-health-missing')
    assert {r['CollectorId'] for r in results['collector-health-missing']} == {'qualification-never'}
    # Compile and execute the remaining production query files in the real workspace.
    for name in ('source-transport-errors', 'destination-credential', 'syslog-tls-expiry'):
        results[name] = rule(state, name)
        assert {r['CollectorId'] for r in results[name]} == {'qualification-pressure'}, name
    tls_rows = {r['Source']: r for r in results['syslog-tls-expiry']}
    assert set(tls_rows) == {'syslog:a13', 'syslog:legacy-no-flags:tls-metadata-unknown',
                             'syslog:crl-missing:tls-metadata-unknown'}, sorted(tls_rows)
    assert not tls_rows['syslog:a13']['TlsMetadataIncomplete']
    assert all(r['TlsMetadataIncomplete'] for source, r in tls_rows.items() if source != 'syslog:a13')
    assert not any(r['CoverageIncomplete'] for r in tls_rows.values())
    save(evidence / 'query-results.json', results)
    print('Pressure queries passed; checking recovery', flush=True)
    ingest(state, [record('qualification-pressure', 'collector_health', healthy)])
    wait_rows(state, 4)
    for name in ('queue-storage', 'queue-backlog', 'dead-letters', 'source-overdue'):
        results[name + '-recovered'] = rule(state, name)
        assert not results[name + '-recovered'], name
    save(evidence / 'query-results.json', results)


def owned_user_grants(state):
    if not state.get('ingestionRoleCreationAttempted') and not state.get('ingestionRoleAssignmentId'):
        return []
    scope = '/subscriptions/' + SUB + '/resourceGroups/' + state['group']
    scope += '/providers/Microsoft.Insights/dataCollectionRules/qualification-dcr'
    if state.get('dcrId', '').lower() != scope.lower():
        raise RuntimeError('Temporary role scope mismatch')
    principal = state.get('ingestionPrincipalId')
    assignment = state.get('ingestionRoleAssignmentId')
    if principal:
        uuid.UUID(principal)
    prefix = scope.lower() + '/providers/microsoft.authorization/roleassignments/'
    if assignment:
        if not assignment.lower().startswith(prefix):
            raise RuntimeError('Temporary role assignment ownership mismatch')
        uuid.UUID(assignment[len(prefix):])
    if not principal and not assignment:
        raise RuntimeError('Temporary role creation cannot be reconciled')
    # Subscription-level listing also works after the resource group is gone.
    # Filter locally; never issue a broad role-assignment delete.
    grants = az('role', 'assignment', 'list', '--all', '--subscription', SUB) or []
    owned = []
    for grant in grants:
        same_id = assignment and grant.get('id', '').lower() == assignment.lower()
        same_principal = principal and grant.get('principalId', '').lower() == principal.lower()
        in_scope = grant.get('scope', '').lower() == scope.lower()
        if same_id and not in_scope:
            raise RuntimeError('Temporary role assignment scope changed')
        if in_scope and (same_id or same_principal):
            if not grant.get('id', '').lower().startswith(prefix):
                raise RuntimeError('Temporary role assignment ID is outside its scope')
            uuid.UUID(grant['id'][len(prefix):])
            owned.append(grant)
    return owned


def cleanup(state, evidence):
    print('Deleting the owned Azure resource group and temporary user grant', flush=True)
    verify_account()
    if state.get('group') != state.get('runId') or not re.fullmatch(r'bower-kql-\d{8}-\d{6}(?:-[a-f0-9]{8})?', state.get('runId', '')):
        raise RuntimeError('Refusing cleanup: invalid run scope')
    exists = az('group', 'exists', '--name', state['group'], '--subscription', SUB)
    if exists:
        if state.get('groupCreationAttempted') is not True:
            raise RuntimeError('Refusing cleanup: group creation was never attempted')
        group = az('group', 'show', '--name', state['group'], '--subscription', SUB)
        tags = group.get('tags') or {}
        if tags.get('Project') != 'bower-lab' or tags.get('RunId') != state['runId']:
            raise RuntimeError('Refusing cleanup: ownership mismatch')
    errors = []
    try:
        for grant in owned_user_grants(state):
            az('role', 'assignment', 'delete', '--ids', grant['id'], '--subscription', SUB)
    except Exception:
        errors.append('temporary role cleanup failed')
    if exists:
        az('group', 'delete', '--name', state['group'], '--subscription', SUB, '--yes')
    exists = az('group', 'exists', '--name', state['group'], '--subscription', SUB)
    roles_absent = False
    try:
        roles_absent = not owned_user_grants(state)
    except Exception:
        errors.append('temporary role absence verification failed')
    save(evidence / 'cleanup.json', {'resourceGroupAbsent': not exists, 'resourceGroup': state['group'],
                                    'ingestionRoleAssignmentAbsent': roles_absent, 'errors': errors})
    if exists or not roles_absent or errors:
        raise RuntimeError('Owned Azure resources or temporary roles are not verified absent')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if not args.apply:
        print('Plan: temporary Australian workspace, Bower DCR, synthetic ingestion/query checks, then delete group.')
        return
    verify_account()
    args.evidence.mkdir(parents=True, exist_ok=False)
    run_id = 'bower-kql-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    state = {'runId': run_id, 'group': run_id, 'subscription': SUB, 'tenant': TENANT,
             'kind': 'live-azure-synthetic-query-qualification', 'collectorDeliveryTest': False}
    save(args.evidence / 'state.json', state)
    files = [Path(__file__).resolve(), REPO / 'deploy/bicep/main.bicep',
             *sorted((REPO / 'deploy/sentinel/monitoring/queries').glob('*.kql'))]
    save(args.evidence / 'provenance.json', {
        'head': subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
        'files': {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}})
    try:
        create_owned_group(state, args.evidence)
        workspace_url = API + '/subscriptions/' + SUB + '/resourceGroups/' + run_id
        workspace_url += '/providers/Microsoft.OperationalInsights/workspaces/' + run_id
        workspace = rest('put', workspace_url + '?api-version=2025-07-01', {
            'location': 'australiaeast', 'tags': {'Project': 'bower-lab', 'RunId': run_id},
            'properties': {'sku': {'name': 'PerGB2018'}, 'retentionInDays': 30,
                           'features': {'disableLocalAuth': True}, 'workspaceCapping': {'dailyQuotaGb': 0.1}}})
        state['workspaceId'] = workspace['properties']['customerId']
        print('Workspace created; deploying Bower ingestion resources', flush=True)
        principal = az('ad', 'signed-in-user', 'show', '--query', 'id')
        outputs = az('deployment', 'group', 'create', '--resource-group', run_id, '--subscription', SUB,
                     '--name', 'bower-ingestion', '--template-file', str(REPO / 'deploy/bicep/main.bicep'),
                     '--parameters', 'workspaceName=' + run_id, 'namePrefix=qualification',
                     '--query', 'properties.outputs')
        state['endpoint'] = outputs['dataCollectionEndpoint']['value']
        state['immutableId'] = outputs['dataCollectionRuleImmutableId']['value']
        state['dcrId'] = '/subscriptions/' + SUB + '/resourceGroups/' + run_id
        state['dcrId'] += '/providers/Microsoft.Insights/dataCollectionRules/qualification-dcr'
        # The production template grants application identities. This disposable query
        # test uses the already signed-in operator, with an explicit DCR-scoped grant.
        state['ingestionPrincipalId'] = principal
        state['ingestionRoleCreationAttempted'] = True
        save(args.evidence / 'state.json', state)
        grant = az('role', 'assignment', 'create', '--assignee-object-id', principal,
                   '--assignee-principal-type', 'User', '--role', '3913510d-42f4-4e42-8a64-420c390055eb',
                   '--scope', state['dcrId'], '--subscription', SUB)
        state['ingestionRoleAssignmentId'] = grant['id']
        save(args.evidence / 'state.json', state)
        qualify(state, args.evidence)
        save(args.evidence / 'result.json', {'passed': True, 'scope': state['kind']})
    except BaseException as error:
        save(args.evidence / 'result.json', {'passed': False, 'failureType': type(error).__name__,
                                           'operation': str(error) if type(error) is RuntimeError else None})
        raise
    finally:
        cleanup(state, args.evidence)


if __name__ == '__main__':
    main()
