#!/usr/bin/env python3
"""Run collectors against a real DCR with deliberately broken Entra credentials.

Operator-sequenced: start a case, send events, break or fix the credential in Entra
or RBAC yourself, restart where the runbook says so, and read the outcome. Every case
has its own port, queue and timeline under WORK/cases/CASE. Nothing printed or written
by this script contains a secret, a token or an event payload.

WORK/lab.json (no secrets):
  {"runId": "bower-...", "tenantId": "...", "dceEndpoint": "https://...",
   "dcrImmutableId": "dcr-...", "streamName": "Custom-BowerSecurity",
   "apps": {"publisher": "<client id>", "verifier": "<client id>"}}
WORK/secrets/ (0700): ingest-token, client secrets or PEM certificates, HMAC keys.

Examples:
  credential-failure-lab.py --work W --collector BIN start revoke --app publisher --secret pub.s1
  credential-failure-lab.py --work W send revoke --tag baseline --count 20
  credential-failure-lab.py --work W outcome revoke
  credential-failure-lab.py --work W scan revoke
"""
import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

STATES = ['queued', 'uploading', 'retrying', 'delivered', 'deadLettered']
JWT = re.compile(rb'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.')


class Lab:
    def __init__(self, work):
        self.work = os.path.abspath(work)
        self.config = json.load(open(os.path.join(self.work, 'lab.json')))
        self.run_id = self.config['runId']
        if not self.run_id.startswith('bower-'):
            raise SystemExit('runId must start with bower-')

    def case_dir(self, case):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,40}', case):
            raise SystemExit('case names are lowercase letters, digits and hyphens')
        path = os.path.join(self.work, 'cases', case)
        os.makedirs(path, mode=0o700, exist_ok=True)
        return path

    def port(self, case):
        # Stable per case name, in 4400-4699; collisions are refused at start.
        return 4400 + int(hashlib.sha256(case.encode()).hexdigest(), 16) % 300

    def secret(self, name):
        return open(os.path.join(self.work, 'secrets', name)).read().strip()

    def record(self, case, entry):
        entry['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(os.path.join(self.case_dir(case), 'timeline.jsonl'), 'a') as handle:
            handle.write(json.dumps(entry) + '\n')

    def request(self, case, path, body=None):
        headers = {'Authorization': 'Bearer ' + self.secret('ingest-token')}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(f'http://127.0.0.1:{self.port(case)}{path}', data=body,
                                         method='POST' if body is not None else 'GET', headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, {}


def start(lab, arguments):
    directory = lab.case_dir(arguments.case)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('AZURE_', 'BOWER_'))}
    environment.update({
        'BOWER_LISTEN_URL': f'http://127.0.0.1:{lab.port(arguments.case)}',
        'BOWER_QUEUE_PATH': os.path.join(directory, 'queue', 'bower.db'),
        'BOWER_POLICY_DIRECTORY': arguments.policies,
        'BOWER_COLLECTOR_ID': f'{lab.run_id}-{arguments.case}',
        'BOWER_ENVIRONMENT': 'credential-lab',
        'BOWER_SINGLE_TRUST_DOMAIN': 'true',
        'BOWER_INGEST_TOKEN_FILE': os.path.join(lab.work, 'secrets', 'ingest-token'),
        'BOWER_OUTPUT': 'azure-logs-ingestion',
        'BOWER_DCE_ENDPOINT': lab.config['dceEndpoint'],
        'BOWER_DCR_ID': lab.config['dcrImmutableId'],
        'BOWER_STREAM_NAME': lab.config['streamName'],
        'BOWER_DELIVERY_LEASE_SECONDS': '90',
        'BOWER_DELIVERY_TIMEOUT_SECONDS': '60',
        'BOWER_AZURE_CREDENTIAL': 'environment',
        'AZURE_TENANT_ID': arguments.tenant or lab.config['tenantId'],
        'AZURE_CLIENT_ID': lab.config['apps'][arguments.app],
    })
    if arguments.secret:
        environment['AZURE_CLIENT_SECRET'] = lab.secret(arguments.secret)
    if arguments.certificate:
        environment['AZURE_CLIENT_CERTIFICATE_PATH'] = os.path.join(lab.work, 'secrets', arguments.certificate)
    if arguments.privacy_profile:
        environment['BOWER_PRIVACY_PROFILE'] = arguments.privacy_profile
        environment['BOWER_PRIVACY_HMAC_KEY_FILE'] = os.path.join(lab.work, 'secrets', arguments.hmac_key)
        environment['BOWER_PRIVACY_HMAC_KEY_ID'] = arguments.hmac_key_id
    os.makedirs(os.path.join(directory, 'queue'), mode=0o700, exist_ok=True)
    log = open(os.path.join(directory, 'collector.log'), 'ab')
    process = subprocess.Popen([arguments.collector], cwd=directory, env=environment, stdout=log,
                               stderr=subprocess.STDOUT, start_new_session=True)
    with open(os.path.join(directory, 'pid'), 'w') as handle:
        handle.write(str(process.pid))
    binary = os.path.join(os.path.dirname(arguments.collector), 'Bower.Collector.dll')
    lab.record(arguments.case, {
        'action': 'start', 'app': arguments.app, 'tenant': 'override' if arguments.tenant else 'configured',
        'credential': f'secret:{arguments.secret}' if arguments.secret else f'certificate:{arguments.certificate}',
        'collectorSha256': hashlib.sha256(open(binary, 'rb').read()).hexdigest() if os.path.exists(binary) else None})
    for _ in range(60):
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{lab.port(arguments.case)}/health', timeout=2)
            print(json.dumps({'started': arguments.case, 'pid': process.pid}))
            return
        except OSError:
            if process.poll() is not None:
                raise SystemExit('collector exited; read the case collector.log')
            time.sleep(0.5)
    raise SystemExit('collector did not become healthy')


def stop(lab, arguments):
    path = os.path.join(lab.case_dir(arguments.case), 'pid')
    pid = int(open(path).read())
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(60):
            os.kill(pid, 0)
            time.sleep(0.5)
    except ProcessLookupError:
        pass
    lab.record(arguments.case, {'action': 'stop'})
    print(json.dumps({'stopped': arguments.case}))


def send(lab, arguments):
    accepted, statuses = [], {}
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for index in range(arguments.count):
        event = {
            'schemaVersion': '1.0.0', 'eventId': f'{lab.run_id}-{arguments.case}-{arguments.tag}-{index:05d}',
            'timeGenerated': now, 'eventCategory': 'authentication', 'eventType': 'authentication_failure',
            'eventAction': 'authentication.attempt', 'eventResult': 'failure', 'eventOutcomeReason': 'InvalidPassword',
            'application': {'name': 'credential-lab', 'environment': 'lab'},
            'actor': {'username': f'lab-user-{index % 7}'}, 'source': {'ipAddress': '192.0.2.10'},
            'request': {'correlationId': f'{arguments.case}-{arguments.tag}'}}
        status, body = lab.request(arguments.case, '/v1/events', json.dumps(event).encode())
        statuses[status] = statuses.get(status, 0) + 1
        if status == 202:
            accepted.append(body['eventId'])
    with open(os.path.join(lab.case_dir(arguments.case), f'sent-{arguments.tag}.json'), 'w') as handle:
        json.dump({'tag': arguments.tag, 'count': arguments.count, 'accepted': accepted, 'statuses': statuses}, handle)
    lab.record(arguments.case, {'action': 'send', 'tag': arguments.tag, 'count': arguments.count, 'statuses': statuses})
    print(json.dumps({'tag': arguments.tag, 'statuses': statuses}))


def note(lab, arguments):
    lab.record(arguments.case, {'action': 'change', 'detail': arguments.detail})


def queue_rows(lab, case):
    """Reads a copy of the queue (with its WAL) so a running collector is never disturbed."""
    directory = lab.case_dir(case)
    copy = tempfile.mkdtemp()
    try:
        for part in glob.glob(os.path.join(directory, 'queue', 'bower.db*')):
            shutil.copy(part, copy)
        connection = sqlite3.connect(os.path.join(copy, 'bower.db'))
        try:
            return connection.execute(
                'SELECT event_id, state, last_failure_code, delivery_attempts, delivered_at FROM queue_events').fetchall()
        finally:
            connection.close()
    finally:
        shutil.rmtree(copy)


def outcome(lab, arguments):
    rows = queue_rows(lab, arguments.case)
    states = {}
    for _, state, code, _, _ in rows:
        key = f'{STATES[state] if state < len(STATES) else state}:{code or "-"}'
        states[key] = states.get(key, 0) + 1
    log = open(os.path.join(lab.case_dir(arguments.case), 'collector.log'), errors='replace').read().splitlines()
    warnings = [line for line in log if 'did not deliver' in line]
    status = lab.request(arguments.case, '/v1/status')[1].get('queue') if arguments.live else None
    result = {'case': arguments.case, 'queue': states, 'status': status,
              'deliveryFailureLines': len(warnings), 'lastDeliveryFailure': warnings[-1][:200] if warnings else None}
    lab.record(arguments.case, {'action': 'outcome', 'queue': states})
    print(json.dumps(result))


def scan(lab, arguments):
    """Counts any configured secret value or JWT-shaped string in the queue files, log and status."""
    directory = lab.case_dir(arguments.case)
    secrets = {os.path.basename(path): open(path, 'rb').read().strip()
               for path in glob.glob(os.path.join(lab.work, 'secrets', '*'))}
    targets = {os.path.basename(path): open(path, 'rb').read()
               for path in glob.glob(os.path.join(directory, 'queue', 'bower.db*'))}
    targets['collector.log'] = open(os.path.join(directory, 'collector.log'), 'rb').read()
    targets['status'] = json.dumps(lab.request(arguments.case, '/v1/status')[1]).encode() if arguments.live else b''
    result = {name: {'bytes': len(data), 'jwtShaped': len(JWT.findall(data)),
                     'secretMatches': {key: data.count(value) for key, value in secrets.items() if value and data.count(value)}}
              for name, data in targets.items()}
    print(json.dumps(result))
    if any(item['jwtShaped'] or item['secretMatches'] for item in result.values()):
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--work', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    command = sub.add_parser('start')
    command.add_argument('case')
    command.add_argument('--collector', required=True, help='Bower.Collector apphost')
    command.add_argument('--app', required=True, help='key in lab.json apps')
    group = command.add_mutually_exclusive_group(required=True)
    group.add_argument('--secret', help='file in WORK/secrets holding a client secret')
    group.add_argument('--certificate', help='PEM (certificate and key) in WORK/secrets')
    command.add_argument('--tenant', help='override the tenant (wrong-tenant case)')
    command.add_argument('--policies', default=os.path.join(os.path.dirname(__file__), '..', '..', '..', 'policies', 'default'))
    command.add_argument('--privacy-profile')
    command.add_argument('--hmac-key', default='hmac-k1.key')
    command.add_argument('--hmac-key-id', default='k1')
    command.set_defaults(handler=start)
    command = sub.add_parser('stop')
    command.add_argument('case')
    command.set_defaults(handler=stop)
    command = sub.add_parser('send')
    command.add_argument('case')
    command.add_argument('--tag', required=True)
    command.add_argument('--count', type=int, default=20)
    command.set_defaults(handler=send)
    command = sub.add_parser('note', help='record a credential change you made')
    command.add_argument('case')
    command.add_argument('detail')
    command.set_defaults(handler=note)
    for name, handler in (('outcome', outcome), ('scan', scan)):
        command = sub.add_parser(name)
        command.add_argument('case')
        command.add_argument('--live', action='store_true', help='also read /v1/status from the running collector')
        command.set_defaults(handler=handler)
    arguments = parser.parse_args()
    arguments.handler(Lab(arguments.work), arguments)


if __name__ == '__main__':
    main()
