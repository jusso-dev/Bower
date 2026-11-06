#!/usr/bin/env python3
"""Operator driver for the 72-hour re-soak (RunId bower-resoak-UTCyyyymmdd-HHMMSS).

Builds on the 24-hour soak harness (lab/aws/soak, upgrade-recovery/lab.py profile 'resoak') and
adds: the exact CI candidate with version and hashes, a RunId-owned identity bucket that outlives
the stack, scheduled faults and per-minute canaries run by host agents, and the pre-registered
criteria (preregistration.json). Prints identifiers, digests and metadata only; credentials stay
in the private lab directory and are fetched on the hosts through their instance roles.

  BOWER_LAB_RUN_ID=bower-resoak-... BOWER_LAB_DIR=/private/dir resoak.py COMMAND

  candidate --ci-run ID          download the CI packages (private), record candidate.json
  bucket create|status|delete    the RunId identity bucket (delete needs --reconciled FILE)
  azure                          workspace, DCE/DCR/table, Sentinel, alert rules, second ingest cert
  stage [--plan dryrun]          certificates, signed packs, manifests, plan; upload to the run bucket
  deploy                         host setup in order (each step once; resumes after a failure)
  smoke                          soak agents, then the 15-minute smoke generators
  smoke-export                   after the smoke: DC native window and accepted unions (then reconcile.py smoke)
  start [--plan dryrun]          agents, faults, canaries and generators for the soak itself
  status                         host agent status
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB_PY = HERE.parent / 'upgrade-recovery' / 'lab.py'
ACCOUNT, REGION, PROJECT = '959038055523', 'ap-southeast-2', 'bower-lab'
RUN = os.environ.get('BOWER_LAB_RUN_ID', '')
if not re.fullmatch(r'bower-resoak-\d{8}-\d{6}', RUN):
    raise SystemExit('BOWER_LAB_RUN_ID must be bower-resoak-UTCyyyymmdd-HHMMSS')
LAB = Path(os.environ['BOWER_LAB_DIR']).resolve()
EVIDENCE_BUCKET = RUN + '-ids'
ENV = {**os.environ, 'BOWER_LAB_PROFILE': 'resoak', 'BOWER_LAB_CIDR': '172.31.248.0/24'}
PLAN_FILE = HERE / 'preregistration.json'
DOMAIN = 'bower.lab'
# Expiry guards (README, "Expiry guards"): every host powers itself off (shutdown behaviour
# terminate) GUARD_AFTER_START seconds after the soak start, i.e. 4 hours after the 72-hour end;
# the stack's scheduler terminates the hosts at its own expiry; the Azure resource group deletes
# itself AZURE_GUARD_AFTER_AWS seconds after the AWS expiry, leaving a day to reconcile.
GUARD_AFTER_START = 76 * 3600
AZURE_GUARD_AFTER_AWS = 24 * 3600
# The dry run keeps every mechanism and shortens the clock: 40 minutes, one fault (a 10-minute
# destination outage on both collectors), canaries on.
DRY_RUN_SECONDS, DRY_RUN_FAULT = 2400, {'id': 'D01', 'kind': 'destination-outage', 'at': 600, 'durationSeconds': 600,
                                        'hosts': ['Linux', 'Wec'], 'collectors': ['linux', 'windows'], 'restarts': [], 'reboots': [],
                                        'impactAllowanceSeconds': 900,
                                        'alertsPermitted': ['collector-health-missing', 'queue-backlog', 'destination-freshness', 'table-no-ingestion'],
                                        'alertsRequiredAnyOf': [],
                                        'expected': 'Dry run: events queue during the 10-minute block, delivery resumes after restore, 0 missing.'}


# ------------------------------------------------------------------ helpers

def sh(*args, timeout=900, env=None, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError('%s failed (%d): %s' % (' '.join(map(str, args[:3])), result.returncode, result.stderr.strip()[-600:]))
    return result.stdout


def aws(*args, raw=False, check=True):
    out = sh('aws', '--profile', 'homelab-admin', '--region', REGION, *args, '--output', 'json', check=check)
    return out if raw else (json.loads(out) if out.strip() else {})


def verify_account():
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise SystemExit('Unexpected AWS account; nothing attempted')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def save(name, data):
    (LAB / name).write_text(json.dumps(data, indent=1) + '\n')


def load(name):
    return json.loads((LAB / name).read_text())


def lab(*args, timeout=900):
    return sh(sys.executable, str(LAB_PY), *args, env=ENV, timeout=timeout)


def state():
    return load('state.json')


def log(record):
    record = {'at': dt.datetime.now(dt.timezone.utc).isoformat(), **record}
    with (LAB / 'resoak-steps.jsonl').open('a') as stream:
        stream.write(json.dumps(record) + '\n')
    print(json.dumps(record), flush=True)


def run_on(host, script, *params, wait=True, timeout=10800):
    """lab.py run + wait. Returns (status, stdout). Never passes secrets (lab.py renders public values)."""
    cid = lab('run', host, str(script), *params).strip().splitlines()[-1]
    if not wait:
        return 'Sent', cid
    output = lab('wait', cid, timeout=timeout + 300)
    status = json.loads(output.splitlines()[0])['Status']
    return status, '\n'.join(output.splitlines()[1:])


def wait_online(host, settle=60, limit=1800):
    """After a reboot: SSM online again and a command round-trip succeeds."""
    time.sleep(settle)
    deadline = time.time() + limit
    probe = HERE / ('probe.ps1' if host in ('Dc', 'Wec') else 'probe.sh')
    while time.time() < deadline:
        try:
            if json.loads(lab('status'))['ssm'].get(host) == 'Online':
                status, _ = run_on(host, probe, timeout=300)
                if status == 'Success':
                    return
        except (RuntimeError, ValueError, KeyError):
            pass
        time.sleep(20)
    raise RuntimeError(host + ' did not come back online')


def plan_for(kind):
    plan = json.loads(PLAN_FILE.read_text())
    if kind == 'dryrun':
        plan['dryRun'] = True
        plan['profile']['soakSeconds'] = DRY_RUN_SECONDS
        plan['faults'] = [DRY_RUN_FAULT]
        plan['note'] = 'Dry-run derivative of preregistration.json: shorter clock, one fault. Not the registered plan.'
    return plan


# ------------------------------------------------------------------ candidate

def candidate(ci_run):
    """The exact CI build: commit, run number (build), version from the package names, hashes."""
    info = json.loads(sh('gh', 'run', 'view', str(ci_run), '--repo', 'jusso-dev/Bower', '--json',
                         'headSha,headBranch,event,conclusion,number,workflowName,jobs,url'))
    if info['workflowName'] != 'CI':
        raise SystemExit('Not a CI workflow run')
    # The soak counts only for current main: the CI commit must be origin/main's head (fetched
    # now) and inside this harness's history, so the packs built from this tree match it.
    sh('git', '-C', str(REPO), 'fetch', '--quiet', 'origin', 'main')
    main_head = sh('git', '-C', str(REPO), 'rev-parse', 'origin/main').strip()
    if info['headBranch'] != 'main' or info['headSha'] != main_head:
        raise SystemExit('CI run %s built %s@%s, not origin/main %s' % (ci_run, info['headBranch'], info['headSha'][:12], main_head[:12]))
    if subprocess.run(['git', '-C', str(REPO), 'merge-base', '--is-ancestor', info['headSha'], 'HEAD']).returncode:
        raise SystemExit('The harness checkout does not contain the candidate commit; rebase it on origin/main')
    jobs = {j['name']: j['conclusion'] for j in info['jobs']}
    # The soak needs the packages built, tested and installed. Other failed jobs are recorded in
    # jobsNotSucceeded (release check 0, CI green, is separate from the soak).
    needed = ('build-test', 'package-linux', 'package-windows', 'install-linux', 'install-windows', 'publish (osx-arm64, macos-latest)')
    if any(jobs.get(name) != 'success' for name in needed):
        raise SystemExit('The CI run did not build and install the packages (a push run skips them; dispatch CI on main)')
    root = private(LAB / 'candidate')
    for name in ('bower-packages-linux', 'bower-packages-windows', 'bower-osx-arm64'):
        target = root / name
        if not target.exists():
            sh('gh', 'run', 'download', str(ci_run), '--repo', 'jusso-dev/Bower', '-n', name, '-D', str(target), timeout=1800)
    rpm = [p for p in (root / 'bower-packages-linux').rglob('bower-collector-*.x86_64.rpm') if 'upgrade' not in p.name]
    msi = [p for p in (root / 'bower-packages-windows').rglob('bower-collector-*-x64.msi')]
    if len(rpm) != 1 or len(msi) != 1:
        raise SystemExit('Expected exactly one collector RPM and one MSI in the CI artifacts')
    version = re.fullmatch(r'bower-collector-(.+)-x64\.msi', msi[0].name).group(1)
    rpm_version = re.fullmatch(r'bower-collector-(.+)\.x86_64\.rpm', rpm[0].name).group(1)
    cli = next((root / 'bower-osx-arm64').rglob('bower'), None)
    if cli:
        cli.chmod(0o755)
    reported = sh(str(cli), '--version').strip() if cli else None
    failed = sorted(j['name'] for j in info['jobs'] if j['conclusion'] not in ('success', 'skipped'))
    record = {'ciRun': int(ci_run), 'ciRunUrl': info['url'], 'buildNumber': info['number'], 'event': info['event'],
              'ref': info['headBranch'], 'commit': info['headSha'], 'conclusion': info['conclusion'], 'jobsNotSucceeded': failed,
              'harnessCommit': sh('git', '-C', str(REPO), 'rev-parse', 'HEAD').strip(),
              'version': version,
              'rpm': {'name': rpm[0].name, 'path': rpm[0].relative_to(root).as_posix(), 'version': rpm_version,
                      'sha256': sha256(rpm[0]), 'bytes': rpm[0].stat().st_size},
              'msi': {'name': msi[0].name, 'path': msi[0].relative_to(root).as_posix(), 'sha256': sha256(msi[0]), 'bytes': msi[0].stat().st_size},
              'cli': {'path': cli.relative_to(root).as_posix() if cli else None, 'reports': reported},
              'signature': 'unsigned (release signing is deferred)'}
    if reported and reported != 'bower ' + version:
        raise SystemExit('CLI version %r does not match the package version %s' % (reported, version))
    save('candidate.json', record)
    print(json.dumps(record, indent=1))


# ------------------------------------------------------------------ identity bucket

def bucket(action, reconciled=None):
    verify_account()
    if action == 'create':
        aws('s3api', 'create-bucket', '--bucket', EVIDENCE_BUCKET, '--create-bucket-configuration', 'LocationConstraint=' + REGION)
        aws('s3api', 'put-bucket-tagging', '--bucket', EVIDENCE_BUCKET, '--tagging',
            json.dumps({'TagSet': [{'Key': 'Project', 'Value': PROJECT}, {'Key': 'RunId', 'Value': RUN}]}))
        aws('s3api', 'put-public-access-block', '--bucket', EVIDENCE_BUCKET, '--public-access-block-configuration',
            'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true')
        aws('s3api', 'put-bucket-encryption', '--bucket', EVIDENCE_BUCKET, '--server-side-encryption-configuration',
            json.dumps({'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}))
        aws('s3api', 'put-bucket-policy', '--bucket', EVIDENCE_BUCKET, '--policy', json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*', 'Resource': ['arn:aws:s3:::' + EVIDENCE_BUCKET, 'arn:aws:s3:::' + EVIDENCE_BUCKET + '/*'],
             'Condition': {'Bool': {'aws:SecureTransport': 'false'}}}]}))
        # Independent expiry guard: objects expire after 30 days even if teardown is never run.
        aws('s3api', 'put-bucket-lifecycle-configuration', '--bucket', EVIDENCE_BUCKET, '--lifecycle-configuration',
            json.dumps({'Rules': [{'ID': 'Expire', 'Status': 'Enabled', 'Filter': {}, 'Expiration': {'Days': 30},
                                   'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 1}}]}))
    tags = {t['Key']: t['Value'] for t in aws('s3api', 'get-bucket-tagging', '--bucket', EVIDENCE_BUCKET)['TagSet']}
    if tags != {'Project': PROJECT, 'RunId': RUN}:
        raise SystemExit('Identity bucket is not owned by this run')
    if action == 'delete':
        # Only after the final reconciliation exists: the lists are the only way to recompute it.
        if not reconciled or not json.loads(Path(reconciled).read_text()).get('runId') == RUN:
            raise SystemExit('--reconciled must name this run\'s final reconciliation report')
        sh('aws', '--profile', 'homelab-admin', '--region', REGION, 's3', 'rm', 's3://' + EVIDENCE_BUCKET, '--recursive', '--only-show-errors')
        aws('s3api', 'delete-bucket', '--bucket', EVIDENCE_BUCKET)
        print(json.dumps({'deleted': EVIDENCE_BUCKET}))
        return
    listing = aws('s3api', 'list-objects-v2', '--bucket', EVIDENCE_BUCKET, '--query', '{n: KeyCount, keys: Contents[].Key}')
    print(json.dumps({'bucket': EVIDENCE_BUCKET, 'tags': tags, 'objects': listing.get('n'), 'sample': (listing.get('keys') or [])[:20]}))


# ------------------------------------------------------------------ Azure

def azure():
    script = HERE.parent / 'monitoring' / 'azure-environment.py'
    directory = private(LAB / 'azure')
    py = lambda *a, **k: sh(sys.executable, str(script), *a, '--state-dir', str(directory), timeout=k.get('timeout', 2400))
    state_file = directory / 'azure-state.json'
    if not state_file.exists():
        hours = -(-(azure_guard_at() - int(time.time())) // 3600)
        log({'azure': 'prepare', 'out': py('prepare', '--apply', '--run-id', RUN, '--credential-days', '7', '--expires-hours', str(hours))})
    current = json.loads(state_file.read_text())
    if not current.get('outputs'):
        log({'azure': 'plan', 'out': py('plan')[:400]})
        log({'azure': 'apply', 'out': py('apply', '--apply')[:600]})
    current = json.loads(state_file.read_text())
    if not current.get('sentinelResourceId'):
        log({'azure': 'sentinel', 'out': py('sentinel', '--apply')})
    current = json.loads(state_file.read_text())
    if not current['identities']['ingest'].get('nextCertificatePath'):
        log({'azure': 'add-ingest-credential', 'out': py('add-ingest-credential', '--apply')})
    current = json.loads(state_file.read_text())
    marker = directory / 'monitoring-deployed.json'
    if not marker.exists():
        rules = json.loads(sh('az', 'monitor', 'data-collection', 'rule', 'list', '--resource-group', current['group'],
                              '--subscription', current['subscription'], '--only-show-errors', '-o', 'json'))
        if len(rules) != 1:
            raise SystemExit('Expected one DCR in the run resource group')
        expected = json.dumps([RUN + '-linux', RUN + '-windows'])
        deployment = json.loads(sh('az', 'deployment', 'group', 'create', '--name', RUN + '-monitoring', '--resource-group', current['group'],
                                   '--subscription', current['subscription'], '--template-file', str(REPO / 'deploy/sentinel/monitoring/monitoring.bicep'),
                                   '--parameters', 'workspaceName=' + current['workspaceName'], 'dataCollectionRuleName=' + rules[0]['name'],
                                   'namePrefix=' + RUN, 'enabled=true', 'expectedCollectorIds=' + expected,
                                   'tags={"Project":"%s","RunId":"%s"}' % (PROJECT, RUN),
                                   '--only-show-errors', '-o', 'json', timeout=1800))
        marker.write_text(json.dumps({'state': deployment['properties']['provisioningState'], 'dcr': rules[0]['name'],
                                      'expectedCollectorIds': json.loads(expected)}) + '\n')
    guard = directory / 'expiry-guard-deployed.json'
    if not guard.exists():
        guard.write_text(json.dumps(azure_guard(current, iso(azure_guard_at()))) + '\n')
    print(json.dumps({'group': current['group'], 'workspaceId': current['workspaceId'], 'monitoring': json.loads(marker.read_text()),
                      'expiryGuard': json.loads(guard.read_text())}))


def azure_guard(current, delete_at, group=None):
    """The Azure expiry guard (azure-expiry-guard.json): a Logic App in the run's group deletes the
    workspace (forced) and the group at delete_at, even if nobody returns."""
    group = group or current['group']
    tags = {t: v for t, v in json.loads(sh('az', 'group', 'show', '--name', group, '--subscription', current['subscription'],
                                             '--only-show-errors', '-o', 'json')).get('tags', {}).items()}
    if tags.get('Project') != PROJECT or tags.get('RunId') != RUN:
        raise SystemExit('Resource group is not owned by this run')
    if json.loads(sh('az', 'provider', 'show', '--namespace', 'Microsoft.Logic', '--subscription', current['subscription'],
                     '--only-show-errors', '-o', 'json'))['registrationState'] != 'Registered':
        sh('az', 'provider', 'register', '--namespace', 'Microsoft.Logic', '--subscription', current['subscription'], '--wait',
           '--only-show-errors', timeout=900)
    deployment = json.loads(sh('az', 'deployment', 'group', 'create', '--name', group + '-expiry', '--resource-group', group,
                               '--subscription', current['subscription'], '--template-file', str(HERE / 'azure-expiry-guard.json'),
                               '--parameters', 'deleteAt=' + delete_at, 'workspaceName=' + current['workspaceName'],
                               'tags=' + json.dumps({'Project': PROJECT, 'RunId': RUN, 'ExpiresAt': delete_at}),
                               '--only-show-errors', '-o', 'json', timeout=1200))
    return {'state': deployment['properties']['provisioningState'], 'deleteAt': delete_at,
            'workflowId': deployment['properties']['outputs']['workflowId']['value']}


# ------------------------------------------------------------------ staging

OPENSSL = next((p for p in ('/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl') if os.path.exists(p)), 'openssl')


def openssl(*args):
    # Keys use named curves: OpenSSL 3 on the hosts refuses explicit EC parameters (macOS LibreSSL's default).
    sh(OPENSSL, *args)


def issue(ca_dir, out, name, usage, san, days=30, key=None):
    key = key or out / (name + '-key.pem')
    if not key.exists():
        openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-pkeyopt', 'ec_param_enc:named_curve', '-out', str(key))
    csr, ext = out / (name + '.csr'), out / (name + '.ext')
    openssl('req', '-new', '-key', str(key), '-subj', '/CN=' + san[0], '-out', str(csr))
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=' + usage
                   + '\nsubjectAltName=' + ','.join(('IP:' if re.fullmatch(r'[0-9.]+', s) else 'DNS:') + s for s in san) + '\n')
    openssl('x509', '-req', '-in', str(csr), '-CA', str(ca_dir / 'ca.pem'), '-CAkey', str(ca_dir / 'ca-key.pem'), '-CAcreateserial',
            '-days', str(days), '-extfile', str(ext), '-out', str(out / (name + '.pem')))
    csr.unlink()
    ext.unlink()
    return out / (name + '.pem'), key


def manifest(directory, role, names):
    files = {n: {'sha256': sha256(directory / n), 'bytes': (directory / n).stat().st_size} for n in names}
    path = directory / 'manifest.json'
    path.write_text(json.dumps({'schemaVersion': 1, 'runId': RUN, 'role': role, 'files': files}, indent=1) + '\n')
    return sha256(path)


def stage(plan_kind):
    verify_account()
    lab_state, cand = state(), load('candidate.json')
    azure_state = json.loads((LAB / 'azure' / 'azure-state.json').read_text())
    outputs = lab_state['outputs']
    root = private(LAB / 'stage')
    pki = private(root / 'pki')
    if not (pki / 'ca.pem').exists():
        openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-pkeyopt', 'ec_param_enc:named_curve', '-out', str(pki / 'ca-key.pem'))
        openssl('req', '-x509', '-new', '-key', str(pki / 'ca-key.pem'), '-days', '30', '-subj', '/CN=Bower lab ' + RUN,
                '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', str(pki / 'ca.pem'))
        issue(pki, pki, 'server', 'serverAuth', ['collector-a.' + DOMAIN, outputs['LinuxIp']])
        issue(pki, pki, 'server-next', 'serverAuth', ['collector-a.' + DOMAIN, outputs['LinuxIp']])
        issue(pki, pki, 'sender-r', 'clientAuth', ['sender-r.' + DOMAIN, outputs['SenderIp']])
    # Packs signed by a run key with the candidate's own CLI.
    packs = private(root / 'packs')
    cli = str(LAB / 'candidate' / cand['cli']['path'])
    if not (packs / 'keys' / 'lab-pack.pub.pem').exists():
        sh(cli, 'keys', 'generate', '--out-dir', str(packs / 'keys'), '--name', 'lab-pack')
    built = {}
    for name, source in (('syslog-reliability', HERE.parent / 'packs' / 'syslog-reliability'), ('windows-security-logon', REPO / 'packs' / 'windows-security-logon')):
        out = packs / name
        if not out.exists():
            sh(cli, 'pack', 'build', str(source), '--key', str(packs / 'keys' / 'lab-pack.key.pem'), '--out', str(out))
        archive = next(out.glob('*.bowerpack'))
        sh(cli, 'pack', 'test', str(archive), '--trusted-key', str(packs / 'keys' / 'lab-pack.pub.pem'))
        built[name] = archive
    secrets_dir = private(root / 'secrets')
    for name, make in (('ingest-token', lambda: secrets.token_urlsafe(32)), ('hmac.key', lambda: base64.b64encode(secrets.token_bytes(32)).decode())):
        if not (secrets_dir / name).exists():
            (secrets_dir / name).write_text(make() + '\n')
    ingest = Path(azure_state['identities']['ingest']['certificatePath'])
    ingest_next = Path(azure_state['identities']['ingest']['nextCertificatePath'])
    out = azure_state['outputs']
    files = {}

    def put(directory, name, source):
        target = private(root / directory) / name
        shutil.copyfile(source, target)
        target.chmod(0o600)
        files.setdefault(directory, []).append(name)
        return target

    health = REPO / 'examples/policies/collector-health/collector-health.yaml'
    tool = HERE.parent / 'scripts' / 'syslog-host.py'
    # Firewall collector (setup-firewall-collector.sh, rpm, RELP).
    q = 'qualification/' + RUN
    for name, source in (('collector.rpm', LAB / 'candidate' / cand['rpm']['path']), ('ingest.pem', ingest),
                         ('ingest-token', secrets_dir / 'ingest-token'), ('syslog-reliability.bowerpack', built['syslog-reliability']),
                         ('pack-signing.pub.pem', packs / 'keys' / 'lab-pack.pub.pem'), ('collector-health.yaml', health),
                         ('server.pem', pki / 'server.pem'), ('server-key.pem', pki / 'server-key.pem'), ('ca.pem', pki / 'ca.pem'),
                         ('syslog-host.py', tool)):
        put(q + '/collector', name, source)
    env = root / q / 'collector' / 'sentinel.env'
    env.write_text('BOWER_OUTPUT=azure-logs-ingestion\nBOWER_DCE_ENDPOINT=%s\nBOWER_DCR_ID=%s\nBOWER_STREAM_NAME=Custom-BowerSecurity\n'
                   'BOWER_AZURE_CREDENTIAL=environment\nAZURE_TENANT_ID=%s\nAZURE_CLIENT_ID=%s\nAZURE_CLIENT_CERTIFICATE_PATH=/etc/bower/secrets/ingest.pem\n'
                   % (out['dataCollectionEndpoint'], out['dataCollectionRuleImmutableId'], azure_state['tenant'], azure_state['identities']['ingest']['appId']))
    env.chmod(0o600)
    files[q + '/collector'].append('sentinel.env')
    collector_manifest = manifest(root / q / 'collector', 'collector', files[q + '/collector'])
    # Sender (setup-firewall-sender.sh, then update-sender-rsyslog.sh with the same helper as .next).
    for name, source in (('sender-r.pem', pki / 'sender-r.pem'), ('sender-r-key.pem', pki / 'sender-r-key.pem'), ('ca.pem', pki / 'ca.pem'),
                         ('syslog-host.py', tool)):
        put(q + '/sender', name, source)
    sender_manifest = manifest(root / q / 'sender', 'sender', files[q + '/sender'])
    put(q + '/sender', 'syslog-host.py.next', tool)
    plan_path = root / q / 'sender' / 'resoak-plan.json'
    if plan_kind == 'registered':
        shutil.copyfile(PLAN_FILE, plan_path)   # byte for byte: the hosts check the registered SHA-256
    else:
        plan_path.write_text(json.dumps(plan_for(plan_kind), indent=1) + '\n')
    # WEC (wec-install.ps1) and its 4625 pack.
    for name, source in (('collector.msi', LAB / 'candidate' / cand['msi']['path']),
                         ('windows-security-logon-1.0.2.bowerpack', built['windows-security-logon']),
                         ('pack-signing.pub.pem', packs / 'keys' / 'lab-pack.pub.pem'),
                         ('Test-BowerCollectorHealth.ps1', REPO / 'deploy/sentinel/monitoring/host/Test-BowerCollectorHealth.ps1'),
                         ('ingest.pem', ingest), ('hmac.key', secrets_dir / 'hmac.key'), ('ingest-token', secrets_dir / 'ingest-token'),
                         ('collector-health.yaml', health)):
        put('soak/wec', name, source)
    sentinel = root / 'soak' / 'wec' / 'sentinel.json'
    sentinel.write_text(json.dumps({'tenant': azure_state['tenant'], 'client': azure_state['identities']['ingest']['appId'],
                                    'dcr': out['dataCollectionRuleImmutableId'], 'dce': out['dataCollectionEndpoint']}))
    files['soak/wec'].append('sentinel.json')
    (root / 'soak' / 'wec' / 'manifest.json').write_text(json.dumps({n: sha256(root / 'soak' / 'wec' / n) for n in
                                                                     ('collector.msi', 'windows-security-logon-1.0.2.bowerpack', 'pack-signing.pub.pem',
                                                                      'Test-BowerCollectorHealth.ps1')}))
    files['soak/wec'].append('manifest.json')
    for name in ('bower-healthcheck.py', 'bower-healthcheck.service', 'bower-healthcheck.timer'):
        put('soak/linux', name, REPO / 'deploy/sentinel/monitoring/host' / name)
    probe = build_probe()
    put('soak/dc', 'Bower.LabProbe.exe', probe)
    put('soak/dc', 'generator-windows.ps1', HERE.parent / 'soak' / 'generator-windows.ps1')
    for name, source in (('server-next.pem', pki / 'server-next.pem'), ('server-next-key.pem', pki / 'server-next-key.pem'), ('ingest-next.pem', ingest_next)):
        put('resoak/linux', name, source)
    put('resoak/wec', 'ingest-next.pem', ingest_next)
    upload(root, lab_state['outputs']['Artifacts'])
    record = {'runId': RUN, 'plan': plan_kind, 'planSha256': sha256(plan_path), 'registeredPlanSha256': sha256(PLAN_FILE),
              'collectorManifestSha256': collector_manifest, 'senderManifestSha256': sender_manifest,
              'toolSha256': sha256(tool), 'probeSha256': sha256(probe), 'generatorSha256': sha256(HERE.parent / 'soak' / 'generator-windows.ps1'),
              'packPublicKeySha256': sha256(packs / 'keys' / 'lab-pack.pub.pem'),
              'packs': {n: {'name': p.name, 'sha256': sha256(p)} for n, p in built.items()},
              'caSha256': sha256(pki / 'ca.pem'), 'serverNextSha256': sha256(pki / 'server-next.pem'),
              'serverNextKeySha256': sha256(pki / 'server-next-key.pem'), 'ingestNextSha256': sha256(ingest_next),
              'certificates': {n: sh(OPENSSL, 'x509', '-in', str(pki / (n + '.pem')), '-noout', '-enddate').strip()
                               for n in ('ca', 'server', 'server-next', 'sender-r')},
              'candidate': {k: cand[k] for k in ('ciRun', 'commit', 'buildNumber', 'version')}}
    save('stage.json', record)
    print(json.dumps(record, indent=1))


def build_probe():
    out = LAB / 'probe'
    exe = out / 'Bower.LabProbe.exe'
    if not exe.exists():
        # A RID-specific publish rewrites packages.lock.json files; restore only the ones it changed.
        changed = lambda: set(sh('git', '-C', str(REPO), 'diff', '--name-only', '--', '*packages.lock.json').split())
        before = changed()
        dotnet = os.path.expanduser('~/.dotnet/dotnet')
        sh(dotnet, 'publish', str(HERE.parent / 'upgrade-recovery' / 'probe'), '-c', 'Release', '-r', 'win-x64', '--self-contained',
           '-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true', '-o', str(out), env={**os.environ, 'DOTNET_ROOT': os.path.expanduser('~/.dotnet')}, timeout=1800)
        rewritten = sorted(changed() - before)
        if rewritten:
            sh('git', '-C', str(REPO), 'checkout', '--', *rewritten)
    return exe


def upload(root, bucket_name):
    tags = {t['Key']: t['Value'] for t in aws('s3api', 'get-bucket-tagging', '--bucket', bucket_name)['TagSet']}
    if tags.get('Project') != PROJECT or tags.get('RunId') != RUN:
        raise SystemExit('Run bucket is not owned by this run')
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative.startswith(('pki/', 'packs/', 'secrets/')):
            continue   # private material is uploaded only as the named copies above
        sh('aws', '--profile', 'homelab-admin', '--region', REGION, 's3', 'cp', '--only-show-errors', '--sse', 'AES256',
           str(path), 's3://' + bucket_name + '/artifacts/' + relative)


# ------------------------------------------------------------------ deployment

def steps():
    s, st = state()['outputs'], load('stage.json')
    up = HERE.parent / 'upgrade-recovery' / 'scripts'
    soak, mon = HERE.parent / 'soak', HERE.parent / 'monitoring'
    return [
        ('dc-init', 'Dc', up / 'init.ps1', [], 'reboot'),
        ('wec-init', 'Wec', up / 'init.ps1', [], 'reboot'),
        ('dc-forest', 'Dc', up / 'dc.ps1', [], 'reboot'),
        ('wec-join', 'Wec', up / 'join.ps1', [], 'reboot'),
        ('wec-subscription', 'Wec', soak / 'wec-subscription.ps1', ['READ_EXISTING=false'], None),
        ('dc-forwarder', 'Dc', soak / 'dc-forwarder.ps1', ['TARGET=BOWERWEC'], None),
        ('collector', 'Linux', mon / 'setup-firewall-collector.sh',
         ['env:BOWER_ARTIFACT_MANIFEST_SHA256=' + st['collectorManifestSha256'], 'env:BOWER_SYSLOG_SENDER_IP=' + s['SenderIp'],
          'env:BOWER_SYSLOG_PROTOCOL=relp', 'env:BOWER_COLLECTOR_PACKAGE=rpm', 'env:BOWER_QUEUE_RETENTION_HOURS=2'], None),
        ('sender', 'Sender', mon / 'setup-firewall-sender.sh',
         ['env:BOWER_ARTIFACT_MANIFEST_SHA256=' + st['senderManifestSha256'], 'env:BOWER_SYSLOG_COLLECTOR_IP=' + s['LinuxIp'],
          'env:BOWER_SYSLOG_TRANSPORT=relp'], None),
        ('sender-rsyslog-8.2610', 'Sender', mon / 'update-sender-rsyslog.sh', ['env:BOWER_TOOL_SHA256=' + st['toolSha256']], None),
        ('wec-collector', 'Wec', soak / 'wec-install.ps1', [], None),
    ]


def deploy(only=None):
    verify_account()
    done = {json.loads(l)['step'] for l in (LAB / 'resoak-steps.jsonl').read_text().splitlines()
            if '"status": "Success"' in l} if (LAB / 'resoak-steps.jsonl').exists() else set()
    for name, host, script, params, after in steps():
        if name in done or (only and name != only):
            continue
        status, out = run_on(host, script, *params)
        log({'step': name, 'host': host, 'status': status, 'output': out[-1500:]})
        if status != 'Success':
            raise SystemExit('Step %s failed; fix and rerun deploy (completed steps are skipped)' % name)
        if after == 'reboot':
            wait_online(host, settle=90)
    print(json.dumps({'deployed': True}))


def times(kind):
    """Smoke in 12 minutes (the three soak agents install first); the soak at the next hh:05 at
    least 20 minutes after the smoke ends, so the smoke is reconciled before the clock starts."""
    now = int(time.time())
    smoke = (now // 60 + 12) * 60
    earliest = smoke + 900 + 1200
    soak = earliest - earliest % 3600 + 300
    if soak < earliest:
        soak += 3600
    seconds = plan_for(kind)['profile']['soakSeconds']
    return {'smokeStart': smoke, 'smokeSeconds': 900, 'soakStart': soak, 'soakSeconds': seconds}


def agents(run, st):
    """The 24-hour soak's agents, installed before the smoke: 5-minute samples, accepted-identity
    unions, the DC's hourly native exporter; all upload to the run and identity buckets."""
    soak = HERE.parent / 'soak'
    common = ['SMOKE_START=%d' % run['smokeStart'], 'SOAK_START=%d' % run['soakStart'], 'SOAK_SECONDS=%d' % run['soakSeconds'],
              'PROBE_SHA256=' + st['probeSha256']]
    return [
        ('agent-linux', 'Linux', soak / 'collector-agent.sh', ['env:BOWER_SOAK_ACTION=install', 'env:BOWER_SOAK_START=%d' % run['soakStart'],
                                                               'env:BOWER_SOAK_SECONDS=%d' % run['soakSeconds']]),
        ('agent-wec', 'Wec', soak / 'wec-agent.ps1', ['ACTION=install', 'SOAK_START=%d' % run['soakStart'], 'SOAK_SECONDS=%d' % run['soakSeconds'],
                                                      'PROBE_SHA256=' + st['probeSha256']]),
        ('agent-dc', 'Dc', soak / 'dc-agent.ps1', ['ACTION=install', 'LABEL=none', 'GEN_START=0', 'GEN_SECONDS=0', 'SMOKE=0',
                                                   'GEN_SHA256=' + st['generatorSha256']] + common),
    ]


def sequence_run(sequence, key):
    done = {json.loads(l).get(key) for l in (LAB / 'resoak-steps.jsonl').read_text().splitlines()
            if '"status": "Success"' in l} if (LAB / 'resoak-steps.jsonl').exists() else set()
    for name, host, script, params in sequence:
        if name in done:
            continue
        status, out = run_on(host, script, *params)
        log({key: name, 'host': host, 'status': status, 'output': out[-1500:]})
        if status != 'Success':
            raise SystemExit('Step %s failed; fix and rerun (completed steps are skipped)' % name)


def smoke(kind):
    verify_account()
    st = load('stage.json')
    if not (LAB / 'run.json').exists():
        run = times(kind)
        run.update(runId=RUN, plan=kind, planSha256=st['planSha256'])
        save('run.json', run)
    run = load('run.json')
    sequence_run(agents(run, st), 'agent')
    soak = HERE.parent / 'soak'
    if time.time() > run['smokeStart'] - 30:
        raise SystemExit('Smoke start passed while installing agents; delete run.json and rerun smoke')
    log({'smoke': 'sender', 'result': run_on('Sender', soak / 'sender-generator.sh', 'env:BOWER_SOAK_ACTION=start', 'env:BOWER_SOAK_LABEL=smoke',
                                              'env:BOWER_SOAK_START=%d' % run['smokeStart'], 'env:BOWER_SOAK_SECONDS=900',
                                              'env:BOWER_SOAK_FIRST=0', 'env:BOWER_SOAK_SMOKE=1')})
    log({'smoke': 'dc', 'result': run_on('Dc', soak / 'dc-agent.ps1', 'ACTION=generator', 'LABEL=smoke', 'GEN_START=%d' % run['smokeStart'],
                                          'GEN_SECONDS=900', 'SMOKE=1', 'GEN_SHA256=' + st['generatorSha256'], 'SMOKE_START=0', 'SOAK_START=0',
                                          'SOAK_SECONDS=0', 'PROBE_SHA256=' + st['probeSha256'])})
    print(json.dumps(run))


def smoke_export():
    """After the smoke: the DC's native window and fresh accepted unions on both collectors."""
    verify_account()
    run, st = load('run.json'), load('stage.json')
    if time.time() < run['smokeStart'] + run['smokeSeconds'] + 60:
        raise SystemExit('The smoke has not finished')
    soak = HERE.parent / 'soak'
    for name, host, script, params in (
            ('smoke-native', 'Dc', soak / 'dc-native-window.ps1', ['NAME=smoke', 'FROM=%d' % run['smokeStart'], 'TO=%d' % (run['smokeStart'] + run['smokeSeconds'] + 60)]),
            # The DC agent uploads generator records every 15 minutes; push the smoke's now.
            ('smoke-dc-tick', 'Dc', HERE / 'dc-tick.ps1', []),
            ('smoke-union-linux', 'Linux', soak / 'collector-agent.sh', ['env:BOWER_SOAK_ACTION=upload']),
            ('smoke-union-wec', 'Wec', soak / 'wec-agent.ps1', ['ACTION=upload', 'SOAK_START=%d' % run['soakStart'], 'SOAK_SECONDS=%d' % run['soakSeconds'],
                                                                'PROBE_SHA256=' + st['probeSha256']])):
        status, out = run_on(host, script, *params)
        log({'smokeExport': name, 'host': host, 'status': status, 'output': out[-800:]})
        if status != 'Success':
            raise SystemExit(name + ' failed')


def start(kind):
    """Agents first (samplers, unions, native exporter, faults, canaries), then the generators."""
    verify_account()
    run, st = load('run.json'), load('stage.json')
    if st['planSha256'] != run['planSha256'] or run['plan'] != kind:
        raise SystemExit('Staged plan differs from the planned run')
    if time.time() > run['soakStart'] - 300:
        raise SystemExit('Too late to start the agents before the soak start; re-plan the times')
    # The stack's own guard must not end the run before the agents publish their final exports.
    if aws_expiry() < run['soakStart'] + run['soakSeconds'] + 7200:
        raise SystemExit('The stack expiry guard fires before the soak end + 2 h; re-plan the stack')
    guard_at = run['soakStart'] + min(GUARD_AFTER_START, run['soakSeconds'] + 4 * 3600)
    soak = HERE.parent / 'soak'
    common = ['SMOKE_START=%d' % run['smokeStart'], 'SOAK_START=%d' % run['soakStart'], 'SOAK_SECONDS=%d' % run['soakSeconds'],
              'PROBE_SHA256=' + st['probeSha256']]
    sequence = [
        ('guard-linux', 'Linux', HERE / 'expiry-guard.sh', ['env:RESOAK_GUARD_ACTION=install', 'env:RESOAK_GUARD_AT=%d' % guard_at]),
        ('guard-sender', 'Sender', HERE / 'expiry-guard.sh', ['env:RESOAK_GUARD_ACTION=install', 'env:RESOAK_GUARD_AT=%d' % guard_at]),
        ('guard-wec', 'Wec', HERE / 'expiry-guard.ps1', ['ACTION=install', 'GUARD_AT=%d' % guard_at]),
        ('guard-dc', 'Dc', HERE / 'expiry-guard.ps1', ['ACTION=install', 'GUARD_AT=%d' % guard_at]),
        ('faults-linux', 'Linux', HERE / 'fault-agent.sh', ['env:RESOAK_ACTION=install', 'env:RESOAK_HOST=Linux', 'env:RESOAK_START=%d' % run['soakStart'],
                                                             'env:RESOAK_PLAN_SHA256=' + st['planSha256'], 'env:RESOAK_SERVER_NEXT_SHA256=' + st['serverNextSha256'],
                                                             'env:RESOAK_SERVER_KEY_NEXT_SHA256=' + st['serverNextKeySha256'],
                                                             'env:RESOAK_INGEST_NEXT_SHA256=' + st['ingestNextSha256']]),
        ('faults-sender', 'Sender', HERE / 'fault-agent.sh', ['env:RESOAK_ACTION=install', 'env:RESOAK_HOST=Sender', 'env:RESOAK_START=%d' % run['soakStart'],
                                                               'env:RESOAK_PLAN_SHA256=' + st['planSha256']]),
        ('faults-wec', 'Wec', HERE / 'fault-agent.ps1', ['ACTION=install', 'RESOAK_START=%d' % run['soakStart'], 'PLAN_SHA256=' + st['planSha256'],
                                                          'INGEST_NEXT_SHA256=' + st['ingestNextSha256']]),
        ('faults-dc', 'Dc', HERE / 'fault-agent.ps1', ['ACTION=install', 'RESOAK_START=%d' % run['soakStart'], 'PLAN_SHA256=' + st['planSha256'],
                                                        'INGEST_NEXT_SHA256=none']),
        ('gen-sender', 'Sender', soak / 'sender-generator.sh', ['env:BOWER_SOAK_ACTION=start', 'env:BOWER_SOAK_LABEL=soak',
                                                                 'env:BOWER_SOAK_START=%d' % run['soakStart'], 'env:BOWER_SOAK_SECONDS=%d' % run['soakSeconds'],
                                                                 'env:BOWER_SOAK_FIRST=100000']),
        ('gen-dc', 'Dc', soak / 'dc-agent.ps1', ['ACTION=generator', 'LABEL=soak', 'GEN_START=%d' % run['soakStart'],
                                                 'GEN_SECONDS=%d' % run['soakSeconds'], 'SMOKE=0', 'GEN_SHA256=' + st['generatorSha256']] + common),
    ]
    sequence_run(sequence, 'start')
    run['startedAt'] = dt.datetime.now(dt.timezone.utc).isoformat()
    run['soakEnd'] = run['soakStart'] + run['soakSeconds']
    run['guards'] = {'hostsPowerOffAt': iso(guard_at), 'stackSchedulerAt': iso(aws_expiry()), 'azureGroupDeleteAt': iso(azure_guard_at())}
    save('run.json', run)
    print(json.dumps({'soakStart': iso(run['soakStart']), 'soakEnd': iso(run['soakEnd']),
                      'finalExportAfter': iso(run['soakEnd'] + 1800), 'guards': run['guards']}))


def aws_expiry():
    return int(dt.datetime.strptime(state()['expiry'], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=dt.timezone.utc).timestamp())


def azure_guard_at():
    return aws_expiry() + AZURE_GUARD_AFTER_AWS


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def status_all():
    run = load('run.json')
    soak = HERE.parent / 'soak'
    for host, script, params in (('Linux', soak / 'collector-agent.sh', ['env:BOWER_SOAK_ACTION=status']),
                                 ('Linux', HERE / 'fault-agent.sh', ['env:RESOAK_ACTION=status']),
                                 ('Sender', HERE / 'fault-agent.sh', ['env:RESOAK_ACTION=status']),
                                 ('Sender', soak / 'sender-generator.sh', ['env:BOWER_SOAK_ACTION=status', 'env:BOWER_SOAK_LABEL=soak']),
                                 ('Wec', soak / 'wec-agent.ps1', ['ACTION=status', 'SOAK_START=%d' % run['soakStart'], 'SOAK_SECONDS=%d' % run['soakSeconds'],
                                                                  'PROBE_SHA256=' + load('stage.json')['probeSha256']]),
                                 ('Wec', HERE / 'fault-agent.ps1', ['ACTION=status', 'RESOAK_START=%d' % run['soakStart'], 'PLAN_SHA256=x', 'INGEST_NEXT_SHA256=x']),
                                 ('Dc', HERE / 'fault-agent.ps1', ['ACTION=status', 'RESOAK_START=%d' % run['soakStart'], 'PLAN_SHA256=x', 'INGEST_NEXT_SHA256=x']),
                                 *((h, HERE / 'expiry-guard.sh', ['env:RESOAK_GUARD_ACTION=status']) for h in ('Linux', 'Sender')),
                                 *((h, HERE / 'expiry-guard.ps1', ['ACTION=status', 'GUARD_AT=0']) for h in ('Wec', 'Dc'))):
        status, out = run_on(host, script, *params, timeout=600)
        print(json.dumps({'host': host, 'script': script.name, 'status': status}))
        print(out[-2500:])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('candidate', 'bucket', 'azure', 'stage', 'deploy', 'smoke', 'smoke-export', 'start', 'status'))
    parser.add_argument('action', nargs='?')
    parser.add_argument('--ci-run')
    parser.add_argument('--plan', choices=('registered', 'dryrun'), default='registered')
    parser.add_argument('--reconciled')
    parser.add_argument('--only')
    args = parser.parse_args()
    private(LAB)
    if args.command == 'candidate':
        candidate(args.ci_run)
    elif args.command == 'bucket':
        bucket(args.action or 'status', args.reconciled)
    elif args.command == 'azure':
        azure()
    elif args.command == 'stage':
        stage(args.plan)
    elif args.command == 'deploy':
        deploy(args.only)
    elif args.command == 'smoke':
        smoke(args.plan)
    elif args.command == 'smoke-export':
        smoke_export()
    elif args.command == 'start':
        start(args.plan)
    else:
        status_all()


if __name__ == '__main__':
    main()
