#!/usr/bin/env python3
"""Reconcile synthetic firewall source, queue metadata and independent Sentinel identities."""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

MAX_ROWS = 200000
MAX_BYTES = 64 * 1024 * 1024
# The installed Track A nftables rule covers ports 4400..4449, with 40,000 IDs per port.
TRACK_A_IDENTITY_LIMIT = 50 * 40000
SUBSCRIPTION = '945092a0-2500-4b25-85a4-99f1c3135906'
TENANT = 'f4f33fb1-b681-40d1-a854-6f888d45b891'
IDENTITY = re.compile(r'a13-n[0-9]{4,5}x[0-9]{5}')
DIGEST = re.compile(r'[0-9a-f]{64}')
COLUMNS = ['EventId', 'Copies', 'FirstGenerated', 'LastGenerated', 'FirstIngested', 'LastIngested']


def read_json(path, maximum=MAX_BYTES):
    with Path(path).open('rb') as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError('Oversized evidence input')
    return json.loads(content)


def stamp(value):
    # .NET round-trip timestamps have seven fractional digits; Python 3.9's
    # fromisoformat accepts only three or six. Validate the exact offset form,
    # then truncate sub-microsecond precision consistently with source IDs.
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})', value):
        raise ValueError('Explicit ISO offset timestamp required')
    normalized = re.sub(r'\.(\d{1,7})(?=Z|[+-])',
                        lambda match: '.' + (match.group(1) + '000000')[:6], value)
    parsed = dt.datetime.fromisoformat(normalized.replace('Z', '+00:00'))
    return parsed.timestamp()


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(ids):
    return hashlib.sha256('\n'.join(sorted(ids)).encode()).hexdigest()


def expected(plan):
    if (plan.get('schemaVersion') != 1 or not re.fullmatch(r'bower-ws6-\d{8}-\d{6}', plan.get('runId', ''))
            or plan.get('collectorId') != plan['runId'] + '-linux' or plan.get('listener') != 'a13'
            or not re.fullmatch(r'[ab]-[a-z-]+', plan.get('scenario', ''))):
        raise ValueError('Invalid plan ownership or scope')
    start, end = plan['startEpoch'], plan['collectNotBeforeEpoch']
    if not all(isinstance(x, (int, float)) and math.isfinite(x) for x in (start, end)) or not 0 < end - start <= 14400:
        raise ValueError('Invalid scenario window')
    ids = set()
    for block in plan['expectedBlocks']:
        match = re.fullmatch(r'nft:A:(\d+):(\d+)', block)
        if not match:
            raise ValueError('Unsupported identity block')
        first, count = map(int, match.groups())
        if not 0 < count <= MAX_ROWS or first + count > TRACK_A_IDENTITY_LIMIT:
            raise ValueError('Identity block out of bounds')
        block_ids = {'a13-n{}x{}'.format(4400 + n // 40000, 20000 + n % 40000) for n in range(first, first + count)}
        if ids & block_ids or len(ids | block_ids) > MAX_ROWS:
            raise ValueError('Overlapping or excessive expected identities')
        ids |= block_ids
    if not ids:
        raise ValueError('No expected identities')
    return ids


def native_summary(plan, reports):
    if len(reports) != len(plan['generations']):
        raise ValueError('Missing or duplicate native generation reports')
    covered = set()
    rates = []
    for generation, report in zip(plan['generations'], reports):
        for key in ('track', 'first', 'count', 'rate'):
            if report.get(key) != generation[key]:
                raise ValueError('Native generation scope mismatch')
        count = generation['count']
        if (report.get('generator') != 'nft' or report.get('sent') != count
                or report.get('nativeCounterDelta', {}).get('A') != count
                or report.get('nativeCounterDelta', {}).get('B') != 0):
            raise ValueError('Native counter reconciliation failed')
        began, ended = stamp(report['startedAt']), stamp(report['endedAt'])
        rate = report['actualRate']
        if (abs(began - generation['startEpoch']) > 5 or ended <= began
                or began < plan['startEpoch'] - 2 or ended > plan['collectNotBeforeEpoch']
                or not isinstance(rate, (int, float)) or not math.isfinite(rate)
                or not .95 * generation['rate'] <= rate <= 1.05 * generation['rate']
                or abs(count / (ended - began) - rate) > max(1, rate * .05)):
            raise ValueError('Native generation timing or traffic rate failed')
        block = dict(plan, expectedBlocks=['nft:A:{}:{}'.format(generation['first'], count)])
        ids = expected(block)
        if covered & ids:
            raise ValueError('Overlapping native generations')
        covered |= ids
        rates.append(rate)
    if covered != expected(plan):
        raise ValueError('Native generation does not cover expected blocks')
    return {'sent': len(covered), 'nativeCounterDelta': len(covered), 'identitySetSha256': digest(covered),
            'actualRates': rates, 'rateTolerancePercent': 5}


def reject_partial(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(word in key.lower() for word in ('error', 'partial', 'continuation', 'nextlink', 'truncat')) and child:
                raise ValueError('Partial, paginated or failed query response')
            reject_partial(child)
    elif isinstance(value, list):
        for child in value:
            reject_partial(child)


def sentinel_rows(data, start, end, cutoff):
    reject_partial(data)
    tables = data.get('tables', [])
    if len(tables) != 1:
        raise ValueError('Unexpected query tables')
    table = tables[0]
    if [column['name'] for column in table['columns']] != COLUMNS or len(table['rows']) > MAX_ROWS:
        raise ValueError('Unexpected query schema or excessive rows')
    result = {}
    for row in table['rows']:
        if (len(row) != 6 or not isinstance(row[0], str) or not IDENTITY.fullmatch(row[0])
                or type(row[1]) is not int or row[1] < 1 or row[0] in result):
            raise ValueError('Malformed or repeated aggregate identity')
        generated = [stamp(row[2]), stamp(row[3])]
        ingested = [stamp(row[4]), stamp(row[5])]
        if not start <= generated[0] <= generated[1] <= end or not start <= ingested[0] <= ingested[1] <= cutoff:
            raise ValueError('Out of scope query timestamps')
        result[row[0]] = row[1]
    return result


def reconcile(plan, plan_hash, pack_hash, queue, native, sentinel, cutoff):
    ids = expected(plan)
    source = native_summary(plan, native)
    if (queue.get('schemaVersion') != 1 or queue.get('runId') != plan['runId']
            or queue.get('collectorId') != plan['collectorId'] or queue.get('scenario') != plan['scenario']
            or queue.get('planSha256') != plan_hash or queue.get('packSha256') != pack_hash
            or queue.get('helperSha256') != plan['sourceSha256']['syslog-host.py']
            or queue.get('startEpoch') != plan['startEpoch'] - 2
            or queue.get('endEpoch') != plan['collectNotBeforeEpoch']
            or queue.get('malformedRows') != 0 or len(queue['rows']) > MAX_ROWS):
        raise ValueError('Queue evidence scope, artifact or malformed-row check failed')
    accepted = set()
    for row in queue['rows']:
        identity = row['eventId']
        if (not IDENTITY.fullmatch(identity) or identity in accepted
                or not plan['startEpoch'] - 2 <= stamp(row['generatedAt']) <= plan['collectNotBeforeEpoch']
                or not plan['startEpoch'] - 2 <= stamp(row['receivedAt']) <= cutoff):
            raise ValueError('Stale, malformed or duplicate queue identity')
        accepted.add(identity)
    actual = sentinel_rows(sentinel, plan['startEpoch'] - 2, plan['collectNotBeforeEpoch'], cutoff)
    destination = set(actual)
    def summary(seen):
        return {'distinctIds': len(seen), 'missing': len(ids - seen), 'extra': len(seen - ids),
                'missingSetSha256': digest(ids - seen), 'extraSetSha256': digest(seen - ids),
                'identitySetSha256': digest(seen)}
    duplicates = sum(actual.values()) - len(actual)
    complete = ids == accepted == destination
    destination_rows = sentinel['tables'][0]['rows']
    ingestion_window = {
        'firstIngested': iso(min(stamp(row[4]) for row in destination_rows)) if destination_rows else None,
        'lastIngested': iso(max(stamp(row[5]) for row in destination_rows)) if destination_rows else None,
    }
    return {'schemaVersion': 1, 'runId': plan['runId'], 'scenario': plan['scenario'], 'collectorId': plan['collectorId'],
            'planSha256': plan_hash, 'packSha256': pack_hash, 'queryCutoff': iso(cutoff),
            'expected': len(ids), 'expectedSetSha256': digest(ids), 'native': source,
            'queue': summary(accepted), 'sentinel': {**summary(destination), **ingestion_window,
                'rows': sum(actual.values()), 'duplicateRows': duplicates},
            'queueMissingAtSentinel': len(accepted - destination), 'sentinelAbsentFromQueue': len(destination - accepted),
            'identityComplete': complete, 'strictPass': complete and duplicates == 0,
            'destinationQueryVerified': complete, 'queryRole': 'verifier', 'scope': 'identity reconciliation only; fault and topology evidence assessed separately'}


def destination_evidence(plan, plan_hash, pack_hash, data, cutoff, workspace, verifier):
    """Project only validated aggregate identities/times; never persist the HTTP envelope."""
    expected(plan)
    if not DIGEST.fullmatch(plan_hash) or not DIGEST.fullmatch(pack_hash):
        raise ValueError('Invalid destination evidence provenance')
    guid = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    if not all(isinstance(value, str) and re.fullmatch(guid, value) for value in (workspace, verifier)):
        raise ValueError('Invalid destination evidence identity')
    found = sentinel_rows(data, plan['startEpoch'] - 2, plan['collectNotBeforeEpoch'], cutoff)
    rows = []
    for original in data['tables'][0]['rows']:
        if original[1] > 9223372036854775807:
            raise ValueError('Destination copy count exceeds signed long')
        rows.append(list(original))
    query = query_text(plan, cutoff)
    return {'schemaVersion': 1, 'recordType': 'firewall-destination-query-evidence',
            'runId': plan['runId'], 'scenario': plan['scenario'], 'collectorId': plan['collectorId'],
            'workspaceId': workspace, 'verifierClientId': verifier,
            'planSha256': plan_hash, 'packSha256': pack_hash,
            'query': {'text': query, 'sha256': hashlib.sha256(query.encode()).hexdigest(),
                      'requestBodySha256': hashlib.sha256(json.dumps({'query': query}).encode()).hexdigest(),
                      'cutoff': iso(cutoff), 'generatedStart': iso(plan['startEpoch'] - 2),
                      'generatedEnd': iso(plan['collectNotBeforeEpoch']), 'apiTimespan': None},
            'verifierSourceSha256': sha(Path(__file__)), 'queryResponseComplete': True,
            'columns': COLUMNS.copy(), 'rows': rows, 'distinctIdentities': len(found),
            'identitySetSha256': digest(found), 'deliveryQualified': False}


def write_destination_evidence(path, evidence):
    content = (json.dumps(evidence, separators=(',', ':')) + '\n').encode('ascii')
    if len(content) > MAX_BYTES:
        raise ValueError('Oversized sanitized destination evidence')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
    return {'file': Path(path).name, 'bytes': len(content),
            'sha256': hashlib.sha256(content).hexdigest(),
            'distinctIdentities': evidence['distinctIdentities']}


def query_text(plan, cutoff):
    expected(plan)  # Validates every interpolated value.
    return '''BowerSecurity_CL
| where CollectorId == "{collector}" and ApplicationName == "nftables-firewall"
    and ApplicationEnvironment == "validation" and EventType == "network_connection_denied"
| where TimeGenerated between (datetime({start}) .. datetime({end}))
| where ingestion_time() <= datetime({cutoff})
| summarize Copies=count(), FirstGenerated=min(TimeGenerated), LastGenerated=max(TimeGenerated),
    FirstIngested=min(ingestion_time()), LastIngested=max(ingestion_time()) by EventId
| project EventId, Copies, FirstGenerated, LastGenerated, FirstIngested, LastIngested
| take {limit}'''.format(collector=plan['collectorId'], start=iso(plan['startEpoch'] - 2),
                        end=iso(plan['collectNotBeforeEpoch']), cutoff=iso(cutoff), limit=MAX_ROWS + 1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verifier_context(directory):
    directory = directory.resolve()
    state = read_json(directory / 'azure-state.json', 65536)
    verifier = state['identities']['verifier']
    certificate = directory / 'verifier-identity.pem'
    cache = directory / 'azure-cli-verifier'
    guid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    if (state['subscription'] != SUBSCRIPTION or state['tenant'] != TENANT
            or not re.fullmatch(guid, state['workspaceId']) or not re.fullmatch(guid, verifier['appId'])
            or Path(verifier['certificatePath']) != certificate or certificate.is_symlink()
            or not certificate.is_file() or certificate.stat().st_mode & 0o077
            or cache.is_symlink() or cache.resolve() == (Path.home() / '.azure').resolve()):
        raise ValueError('Verifier identity, certificate or isolated cache invalid')
    resource = '/subscriptions/' + SUBSCRIPTION + '/resourceGroups/' + state['group'] + '/providers/Microsoft.OperationalInsights/workspaces/' + state['workspaceName']
    if state['workspaceResourceId'].lower() != resource.lower():
        raise ValueError('Workspace resource scope mismatch')
    cache.mkdir(mode=0o700, exist_ok=True)
    os.chmod(cache, 0o700)
    return state, verifier, certificate, cache


def query_live(directory, query, *, timespan_seconds=None):
    payload = {'query': query}
    if timespan_seconds is not None:
        # Scheduled alert validation must use the deployed event-time scan window.
        # Identity reconciliation keeps its explicit query bounds and omits this option.
        if type(timespan_seconds) is not int or not 1 <= timespan_seconds <= 172800:
            raise ValueError('Query timespan must be 1..172800 whole seconds')
        payload['timespan'] = 'PT' + str(timespan_seconds) + 'S'
    state, verifier, certificate, cache = verifier_context(directory)
    environment = {**os.environ, 'AZURE_CONFIG_DIR': str(cache), 'AZURE_CORE_COLLECT_TELEMETRY': 'no'}
    def az(*args):
        result = subprocess.run(['az', *args, '--output', 'json', '--only-show-errors'], env=environment,
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError('Verifier CLI operation failed; credential output suppressed')
        return json.loads(result.stdout) if result.stdout.strip() else None
    az('login', '--service-principal', '--username', verifier['appId'], '--certificate', str(certificate), '--tenant', TENANT)
    az('account', 'set', '--subscription', SUBSCRIPTION)
    account = az('account', 'show')
    if (account['tenantId'] != TENANT or account['id'] != SUBSCRIPTION
            or account['user']['name'].lower() != verifier['appId'] or account['user']['type'].lower() != 'serviceprincipal'):
        raise ValueError('Unexpected authenticated verifier identity')
    token = az('account', 'get-access-token', '--resource', 'https://api.loganalytics.io/')['accessToken']
    request = urllib.request.Request('https://api.loganalytics.io/v1/workspaces/' + state['workspaceId'] + '/query',
                                    data=json.dumps(payload).encode(), method='POST',
                                    headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    del token
    with urllib.request.build_opener(NoRedirect).open(request, timeout=120) as response:
        if response.status != 200 or any(response.headers.get(key) for key in ('x-ms-continuation', 'x-ms-continuation-token', 'Link')):
            raise ValueError('Unexpected or paginated query response')
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError('Oversized query response')
    return json.loads(body), state['workspaceId'], verifier['appId']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--queue', required=True, type=Path)
    parser.add_argument('--native', required=True, type=Path, action='append', help='One JSON generator report per generation, in plan order')
    parser.add_argument('--pack-sha256', required=True)
    parser.add_argument('--azure-state-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--destination-evidence', type=Path, help='Optional new sanitized query-envelope/aggregate-row evidence file')
    args = parser.parse_args()
    if args.destination_evidence is not None:
        if args.destination_evidence.resolve() == args.output.resolve() or any(os.path.lexists(path) for path in (args.output, args.destination_evidence)):
            raise ValueError('Evidence outputs must be distinct new paths')
    if not DIGEST.fullmatch(args.pack_sha256):
        raise ValueError('Invalid signed-pack digest')
    plan, queue = read_json(args.plan), read_json(args.queue)
    native = [read_json(path, 65536) for path in args.native]
    expected(plan)
    native_summary(plan, native)
    cutoff = dt.datetime.now(dt.timezone.utc).timestamp()
    if cutoff < plan['collectNotBeforeEpoch']:
        raise ValueError('Scenario has not completed')
    data, workspace, verifier = query_live(args.azure_state_dir, query_text(plan, cutoff))
    report = reconcile(plan, sha(args.plan), args.pack_sha256, queue, native, data, cutoff)
    report.update(workspaceId=workspace, verifierClientId=verifier,
                  queueEvidenceSha256=sha(args.queue), nativeEvidenceSha256=[sha(path) for path in args.native])
    if args.destination_evidence is not None:
        evidence = destination_evidence(plan, sha(args.plan), args.pack_sha256, data, cutoff, workspace, verifier)
        report['destinationEvidence'] = write_destination_evidence(args.destination_evidence, evidence)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(report))
    return 0 if report['strictPass'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # Do not emit arbitrary input, CLI stderr, HTTP bodies, identities or credentials.
        print(json.dumps({'status': 'failed', 'category': type(error).__name__}), file=sys.stderr)
        sys.exit(2)
