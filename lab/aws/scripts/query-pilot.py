#!/usr/bin/env python3
"""Independently query pilot identities using an already authenticated verifier CLI cache."""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

MAXIMUM_RESPONSE_BYTES = 64 * 1024 * 1024
MAXIMUM_ROWS = 200000
QUERY = '''BowerSecurity_CL
| project EventId, EventType, PolicyHash, TimeGenerated, Ingested=ingestion_time(),
    RawPrivacyMatch=tostring(RawEnvelope) contains "bower-probe"
        or tostring(RawEnvelope) contains "BOWER_DENY"'''


def timestamp(value):
    parsed = dt.datetime.fromisoformat(re.sub(r'\.(\d+)(?=[Z+-])',
        lambda match: '.' + (match.group(1) + '000000')[:6], value).replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('An explicit UTC/offset timestamp is required')
    return parsed


def summarize(rows):
    identities = sorted({row['EventId'] for row in rows})
    latencies = sorted((timestamp(row['Ingested']) - timestamp(row['TimeGenerated'])).total_seconds()
                       for row in rows)
    def quantile(fraction):
        return latencies[math.ceil(len(latencies) * fraction) - 1] if latencies else None
    return {
        'rows': len(rows), 'distinctIds': len(identities),
        'duplicateRows': len(rows) - len(identities),
        'identitySetSha256': hashlib.sha256('\n'.join(identities).encode()).hexdigest(),
        'rawPrivacyMatches': sum(bool(row['RawPrivacyMatch']) for row in rows),
        'policyHashes': sorted({row['PolicyHash'] for row in rows}),
        'negativeLatencyRows': sum(value < 0 for value in latencies),
        'ingestionLatencySeconds': {'p50': quantile(.5), 'p95': quantile(.95),
                                   'p99': quantile(.99), 'maximum': max(latencies) if latencies else None},
    }


def report_for(data, windows_since, linux_since=None):
    if data.get('error'):
        raise ValueError('Partial or failed query results cannot establish delivery')
    tables = data.get('tables', [])
    if len(tables) != 1:
        raise ValueError('Unexpected query result tables')
    table = tables[0]
    columns = [column['name'] for column in table['columns']]
    expected = ['EventId', 'EventType', 'PolicyHash', 'TimeGenerated', 'Ingested', 'RawPrivacyMatch']
    if columns != expected or len(table['rows']) > MAXIMUM_ROWS:
        raise ValueError('Unexpected columns or excessive result rows')
    rows = []
    for values in table['rows']:
        if (len(values) != len(expected) or any(not isinstance(value, str) for value in values[:5])
                or not isinstance(values[5], bool) or not values[0]):
            raise ValueError('Malformed identity metadata')
        rows.append(dict(zip(columns, values)))
    windows = [row for row in rows if row['EventType'] == 'authentication_failure'
               and timestamp(row['TimeGenerated']) >= windows_since]
    report = {
        'queriedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
        'queryStatus': 200, 'queryRole': 'verifier', 'partialError': False,
        'groups': {kind: summarize([row for row in rows if row['EventType'] == kind])
                   for kind in sorted({row['EventType'] for row in rows})},
        'windowsSince': windows_since.isoformat(), 'windowsCampaign': summarize(windows),
    }
    report['connectedSteady'] = {'windows': summarize([row for row in windows
        if timestamp(row['TimeGenerated']) < windows_since + dt.timedelta(seconds=600)])}
    if linux_since is not None:
        linux = [row for row in rows if row['EventType'] == 'network_connection_denied'
                 and timestamp(row['TimeGenerated']) >= linux_since]
        report['linuxSince'] = linux_since.isoformat()
        report['linuxCampaign'] = summarize(linux)
        report['connectedSteady']['linux'] = summarize([row for row in linux
            if timestamp(row['TimeGenerated']) < linux_since + dt.timedelta(seconds=600)])
    return report


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def guid(value):
    if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', value):
        raise argparse.ArgumentTypeError('A GUID is required')
    return value.lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace-id', type=guid, required=True)
    parser.add_argument('--tenant-id', type=guid, required=True)
    parser.add_argument('--verifier-client-id', type=guid, required=True)
    parser.add_argument('--azure-config-dir', type=Path, required=True)
    parser.add_argument('--windows-since', type=timestamp, required=True)
    parser.add_argument('--linux-since', type=timestamp)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = args.azure_config_dir.expanduser().resolve()
    if config == (Path.home() / '.azure').resolve() or not config.is_dir():
        raise ValueError('Use an existing isolated verifier CLI cache, not the operator cache')
    environment = {**os.environ, 'AZURE_CONFIG_DIR': str(config)}
    def az(*arguments):
        process = subprocess.run(['az', *arguments, '--output', 'json'], env=environment,
                                 capture_output=True, text=True, timeout=60)
        if process.returncode:
            raise RuntimeError('Verifier Azure CLI operation failed; no credential output retained')
        return json.loads(process.stdout)
    account = az('account', 'show')
    if (account['tenantId'].lower() != args.tenant_id
            or account['user']['name'].lower() != args.verifier_client_id
            or account['user']['type'].lower() != 'serviceprincipal'):
        raise ValueError('Authenticated verifier identity does not match the declared target')
    token = az('account', 'get-access-token', '--resource', 'https://api.loganalytics.io/')['accessToken']
    request = urllib.request.Request('https://api.loganalytics.io/v1/workspaces/' + args.workspace_id + '/query',
        data=json.dumps({'query': QUERY}).encode(), method='POST',
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    del token
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
            body = response.read(MAXIMUM_RESPONSE_BYTES + 1)
            if response.status != 200 or len(body) > MAXIMUM_RESPONSE_BYTES:
                raise ValueError('Unexpected status or oversized query response')
    except urllib.error.HTTPError as error:
        raise RuntimeError('Verifier query HTTP status ' + str(error.code)) from None
    report = report_for(json.loads(body), args.windows_since, args.linux_since)
    report.update({'workspaceId': args.workspace_id, 'tenantId': args.tenant_id,
                   'verifierClientId': args.verifier_client_id})
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
