#!/usr/bin/env python3
"""Reconcile the 72-hour re-soak against its pre-registered criteria (preregistration.json).

Reuses the 24-hour soak reconciler (lab/aws/soak/reconcile.py) for the identity sets, the
Sentinel queries with the read-only verifier identity, health, privacy, alerts and resource
slopes, and adds what the re-soak registered: canaries, fault windows from the host fault records,
the fault accounting of criteria 2 to 5, per-fault expected outcomes and the candidate version.

  reconcile.py fetch   --lab-dir DIR             # identity bucket (and run bucket) -> DIR/results
  reconcile.py smoke   --lab-dir DIR --out FILE
  reconcile.py interim --lab-dir DIR --out FILE  # the first hour
  reconcile.py final   --lab-dir DIR --out FILE  # after the end + 30 minutes

DIR/run.json, DIR/stage.json and DIR/candidate.json are written by resoak.py. Writes metadata,
counts and digests only, never identity lists.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('soak_reconcile', HERE.parent / 'soak' / 'reconcile.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

CANARY_FIREWALL = re.compile(r'a13-n4399x(\d{5})')
FIREWALL_BULK = base.FIREWALL_ID
SAMPLE_SLACK = 600   # a 5-minute sampler sees a new process up to one interval late; allow two


def configure(run, plan):
    """Point the 24-hour reconciler at this run: ids, times, markers and limits."""
    base.RUN = run['runId']
    base.SMOKE_START, base.SOAK_START, base.SOAK_SECONDS = run['smokeStart'], run['soakStart'], run['soakSeconds']
    base.SMOKE_SECONDS = run.get('smokeSeconds', 900)
    base.COLLECTORS = {'linux': (run['runId'] + '-linux', 'network_connection_denied'),
                       'windows': (run['runId'] + '-windows', 'authentication_failure')}
    base.PRIVACY_MARKERS = tuple(plan['privacyMarkers'])
    base.LATENCY_P99_LIMIT = plan['latencyP99LimitSeconds']


def load_plan(lab, run):
    """The staged plan the hosts ran, which must be the registered file unless this is a dry run."""
    path = lab / 'stage' / 'qualification' / run['runId'] / 'sender' / 'resoak-plan.json'
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != run['planSha256']:
        raise SystemExit('Staged plan differs from the plan the run recorded')
    plan = json.loads(path.read_text())
    registered = hashlib.sha256((HERE / 'preregistration.json').read_bytes()).hexdigest()
    if not plan.get('dryRun') and digest != registered:
        raise SystemExit('The run used a plan that is not the registered preregistration.json')
    return plan, digest, registered


# ------------------------------------------------------------------ fetch

def fetch(lab):
    run = json.loads((lab / 'run.json').read_text())
    if json.loads(base.aws('sts', 'get-caller-identity'))['Account'] != '959038055523':
        raise SystemExit('Unexpected AWS account')
    out = lab / 'results'
    evidence = run['runId'] + '-ids'
    tags = {t['Key']: t['Value'] for t in json.loads(base.aws('s3api', 'get-bucket-tagging', '--bucket', evidence))['TagSet']}
    if tags != {'Project': 'bower-lab', 'RunId': run['runId']}:
        raise SystemExit('Identity bucket is outside this run')
    state = lab / 'state.json'
    if state.exists():
        # The run bucket (while the stack exists) adds the on-demand DC exports; the identity
        # bucket is authoritative and is synced last.
        bucket = json.loads(state.read_text())['outputs']['Artifacts']
        try:
            base.aws('s3', 'sync', 's3://%s/results/soak/%s/' % (bucket, run['runId']), str(out / 'hosts'), '--only-show-errors')
            base.aws('s3', 'sync', 's3://%s/results/sender/soak/%s/' % (bucket, run['runId']), str(out / 'sender'), '--only-show-errors')
        except subprocess.CalledProcessError:
            print(json.dumps({'runBucket': 'unavailable; identity bucket only'}))
    base.aws('s3', 'sync', 's3://%s/hosts/' % evidence, str(out / 'hosts'), '--only-show-errors')
    base.aws('s3', 'sync', 's3://%s/sender/generator/' % evidence, str(out / 'sender'), '--only-show-errors')
    base.aws('s3', 'sync', 's3://%s/sender/resoak/' % evidence, str(out / 'sender' / 'resoak'), '--only-show-errors')
    files = sorted(str(p.relative_to(out)) for p in out.rglob('*') if p.is_file())
    print(json.dumps({'fetched': len(files), 'sample': files[:40]}))


# ------------------------------------------------------------------ faults and windows

def stamp(value):
    return base.stamp_any(value) if value else None


def fault_records(results):
    records = []
    for path in [results / 'sender' / 'resoak' / 'faults.jsonl'] + sorted(results.glob('hosts/*/resoak/faults.jsonl')):
        if path.exists():
            records += [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    return records


def fault_windows(plan, records, start):
    """Actual windows per fault: start = first executed record (else the planned time), end = the
    latest restoration (outages) or start + duration, impact = end + allowance."""
    out = []
    for fault in plan['faults']:
        mine = [r for r in records if r.get('fault') == fault['id']]
        done = [r for r in mine if r.get('step') == 'done']
        begin = min((stamp(r['startedAt']) for r in done), default=start + fault['at'])
        restored = [stamp(r['restoredAt']) for r in mine if r.get('step') == 'restored' and r.get('restoredAt')]
        end = max(restored) if restored else begin + fault.get('durationSeconds', 0)
        hosts = {r.get('host') for r in done}
        out.append({'id': fault['id'], 'kind': fault['kind'], 'collectors': fault['collectors'], 'plannedAt': start + fault['at'],
                    'durationSeconds': fault.get('durationSeconds', 0),
                    'start': begin, 'end': end, 'impactEnd': end + fault['impactAllowanceSeconds'],
                    'alertEnd': end + fault['impactAllowanceSeconds'] + 3600,
                    'executedOn': sorted(h for h in hosts if h), 'expectedHosts': fault['hosts'],
                    'steps': sorted({r.get('step') for r in mine if r.get('step')}),
                    'lateSeconds': max((r.get('lateSeconds', 0) for r in done), default=None),
                    'restores': [{k: r.get(k) for k in ('restoredAt', 'by', 'blockedPackets', 'error')} for r in mine if r.get('step') == 'restored'],
                    'afterReboot': [r.get('bootId') or r.get('bootAt') for r in mine if r.get('step') == 'after-reboot'],
                    'errors': [r.get('error') for r in mine if r.get('step') in ('failed', 'missed')] + [r.get('step') for r in mine if r.get('step') == 'missed'],
                    'restarts': fault['restarts'], 'reboots': fault['reboots'],
                    'alertsPermitted': fault['alertsPermitted'], 'alertsRequiredAnyOf': fault['alertsRequiredAnyOf']})
    return out


def inside(t, windows, key='impactEnd'):
    return next((w for w in windows if w['start'] <= t < w[key]), None)


# ------------------------------------------------------------------ canaries

def firewall_canaries(results, low_minute, high_minute):
    path = results / 'sender' / 'resoak' / 'canary.jsonl'
    records = [json.loads(l) for l in path.read_text().splitlines() if l.strip()] if path.exists() else []
    records = [r for r in records if low_minute <= r['minute'] < high_minute]
    bad = [r['minute'] for r in records if r['exitCode'] != 0 or r['counterDelta'] != 1]
    return {r['id'] for r in records}, {'sent': len(records), 'notCountedExactly': bad,
                                        'minutesWithoutCanary': high_minute - low_minute - len({r['minute'] for r in records})}


def windows_canaries(results, windows, low_minute, high_minute):
    """Canary attempts on the DC (LDAP 49 = a 4625 was written) and the native canary ids (kind column)."""
    path = results / 'hosts' / 'dc' / 'resoak' / 'canary.jsonl'
    records = [json.loads(l) for l in path.read_text(encoding='utf-8-sig').splitlines() if l.strip()] if path.exists() else []
    records = [r for r in records if low_minute <= r['minute'] < high_minute]
    ids = set()
    for name in windows:
        for sub, suffix in (('native', '.ids'), ('manual', '.json.ids')):
            p = results / 'hosts' / 'dc' / sub / (name + suffix)
            if p.exists():
                for line in p.read_text(encoding='utf-8-sig').splitlines():
                    parts = line.split('\t')
                    if len(parts) >= 5 and parts[4] == 'canary':
                        ids.add(parts[3])
                break
    return ids, {'attempts': len(records), 'ldap49': sum(r.get('ldapResultCode') == 49 for r in records),
                 'otherResults': sorted({r.get('ldapResultCode') for r in records} - {49}, key=str),
                 'minutesWithoutCanary': high_minute - low_minute - len({r['minute'] for r in records})}


def canary_report(canary_ids, rows, windows):
    found = {i: rows[i] for i in canary_ids if i in rows}
    lat = {i: base.stamp(r['FirstIngested']) - base.stamp(r['Generated']) for i, r in found.items()}
    outside = [v for i, v in lat.items() if not inside(base.stamp(found[i]['Generated']), windows)]
    return {'native': len(canary_ids), 'atSentinel': len(found), 'missing': len(canary_ids - set(found)),
            'latencySeconds': base.quantiles(list(lat.values())), 'latencyOutsideFaultWindows': base.quantiles(outside),
            'outsideFaultWindowsOver120s': sum(v > 120 for v in outside)}


# ------------------------------------------------------------------ criteria with the registered accounting

def latency_accounting(rows, windows, limit):
    all_lat, outside, hours, per_fault = [], [], {}, {}
    for r in rows.values():
        generated = base.stamp(r['Generated'])
        value = base.stamp(r['FirstIngested']) - generated
        all_lat.append(value)
        w = inside(generated, windows)
        if w:
            per_fault.setdefault(w['id'], []).append(value)
            continue
        outside.append(value)
        hours.setdefault(int((generated - base.SOAK_START) // 3600), []).append(value)
    hourly = {h: base.quantiles(v) for h, v in sorted(hours.items())}
    q = base.quantiles(outside)
    return {'limitSeconds': limit, 'outsideFaultWindows': q, 'includingFaultWindows': base.quantiles(all_lat),
            'pass': q['p99'] is not None and q['p99'] <= limit,
            'hoursAboveLimit': [h for h, v in hourly.items() if v['p99'] is not None and v['p99'] > limit],
            'hourly': hourly, 'perFault': {k: base.quantiles(v) for k, v in per_fault.items()}}


def identities(samples, start, end):
    rows = [r for r in samples if r.get('process') and start <= base.stamp(r['at']) < end]
    seen, boots = {}, {}
    for r in rows:
        p = r['process']
        key = (p['pid'], str(p.get('startTicks') or p.get('startedAt')))
        seen.setdefault(key, base.stamp(r['at']))
        boots.setdefault(r.get('bootId') or r.get('bootAt'), base.stamp(r['at']))
    return sorted(seen.items(), key=lambda x: x[1]), sorted(boots.items(), key=lambda x: x[1])


def restarts_accounting(samples, host, windows, start, end):
    procs, boots = identities(samples, start, end)
    expected_restarts = [w for w in windows if host in w['restarts']]
    expected_boots = [w for w in windows if host in w['reboots']]
    unexplained = []
    for kind, items, allowed in (('process', procs, expected_restarts), ('boot', boots, expected_boots)):
        for _, first_seen in items[1:]:
            if not any(w['start'] <= first_seen <= w['start'] + 900 + SAMPLE_SLACK for w in allowed):
                unexplained.append({'kind': kind, 'firstSeen': base.iso(first_seen)})
    ok = (not unexplained and len(procs) == 1 + len(expected_restarts) and len(boots) == 1 + len(expected_boots))
    return {'processIdentities': len(procs), 'expectedProcessIdentities': 1 + len(expected_restarts),
            'boots': len(boots), 'expectedBoots': 1 + len(expected_boots),
            'identityFirstSeen': [base.iso(t) for _, t in procs], 'unexplained': unexplained, 'pass': bool(procs) and ok}


def growth_accounting(samples, host, windows, start, end):
    """(a) hours 3-24 of the workload; (b) 3 hours after the last scheduled restart to the end."""
    out = {}
    restart_faults = [w for w in windows if host in w['restarts']]
    last = max((w['start'] for w in restart_faults), default=start)
    for name, origin, to_hour in (('hours3to24', start, 24), ('afterLastRestart', last, (end - last) / 3600)):
        if to_hour <= base.GROWTH_FROM_HOUR + 1:
            out[name] = {'evaluable': False, 'reason': 'window shorter than the 3-hour warm-up plus one hour'}
            continue
        saved = base.GROWTH_TO_HOUR
        base.GROWTH_TO_HOUR = to_hour
        try:
            r = base.resources(samples, host, origin, end)
        finally:
            base.GROWTH_TO_HOUR = saved
        out[name] = {'evaluable': True, 'from': base.iso(origin + 3 * 3600), 'to': base.iso(min(end, origin + to_hour * 3600)),
                     'pass': r['criterion3']['pass'], 'flat': r['criterion3']['flat'],
                     **{k: r[k] for k in ('memoryBytes', 'handlesOrFds', 'threads', 'queueDbPlusWalBytes', 'processIdentities')}}
    evaluable = [v for v in out.values() if v['evaluable']]
    out['pass'] = bool(evaluable) and all(v['pass'] and v['processIdentities'] == 1 for v in evaluable)
    out['evaluableWindows'] = len(evaluable)
    return out


def alerts_accounting(alerts, windows, run_id):
    violations, excused = [], []
    for kind in ('alerts', 'incidents'):
        for item in alerts[kind]:
            if not item['activeDuringRun']:
                continue
            rule = item['name'][len(run_id) + 1:] if item['name'].startswith(run_id + '-') else item['name']
            started = stamp(item['startedAt'])
            w = inside(started, windows, 'alertEnd') if started else None
            if kind == 'alerts' and w and rule in w['alertsPermitted'] and rule not in ('syslog-tls-expiry', 'destination-credential'):
                excused.append({'rule': rule, 'fault': w['id'], 'startedAt': item['startedAt'], 'resolvedAt': item['resolvedAt']})
            else:
                violations.append({'kind': kind, 'rule': rule, 'startedAt': item['startedAt'], 'state': item['state']})
    return {'pass': not violations, 'violations': violations, 'excusedByFault': excused}


def health_gaps(verifier, start, end, windows_by_host):
    text = ('BowerSecurity_CL\n| where TimeGenerated >= datetime({a}) and TimeGenerated < datetime({b})\n'
            '| where EventType == "collector_health" and CollectorId startswith "{r}"\n| order by CollectorId asc, TimeGenerated asc\n'
            '| extend Gap=iff(prev(CollectorId) == CollectorId, datetime_diff("second", TimeGenerated, prev(TimeGenerated)), 0)\n'
            '| where Gap > 120\n| project CollectorId, TimeGenerated, Gap\n| take 5000').format(a=base.iso(start), b=base.iso(end), r=base.RUN)
    rows, _ = verifier.query(text)
    out = {}
    for row in rows:
        host = 'linux' if row['CollectorId'].endswith('-linux') else 'windows'
        ended = base.stamp(row['TimeGenerated'])
        w = inside(ended - row['Gap'], windows_by_host[host]) or inside(ended, windows_by_host[host])
        out.setdefault(host, []).append({'endedAt': row['TimeGenerated'], 'gapSeconds': row['Gap'], 'fault': w['id'] if w else None})
    return {h: {'gapsOver120s': v, 'outsideFaultWindows': [g for g in v if not g['fault']]} for h, v in out.items()}


def versions(verifier, start, end):
    text = ('BowerSecurity_CL\n| where TimeGenerated >= datetime({a}) and TimeGenerated < datetime({b})\n'
            '| where CollectorId startswith "{r}"\n| summarize Rows=count() by CollectorId, Version=tostring(RawEnvelope.collector.version)'
            ).format(a=base.iso(start), b=base.iso(end), r=base.RUN)
    return verifier.query(text)[0]


def natural_events(samples_linux, samples_wec, start, end):
    def jobs(samples):
        runs = {}
        for r in samples:
            if start <= base.stamp(r['at']) < end:
                for job, v in (r.get('jobs') or {}).items():
                    if v and v.get('lastRunAt'):
                        runs.setdefault(job, set()).add((v['lastRunAt'], v.get('lastState')))
        return {j: {'runsObserved': len(v), 'states': sorted({s for _, s in v}, key=str)} for j, v in runs.items()}
    wrap = None
    for r in samples_wec:
        f = r.get('forwardedEvents') or {}
        if f.get('maxBytes') and f.get('fileBytes', 0) >= f['maxBytes'] - 64 * 1024 * 1024:
            wrap = {'firstFullSampleAt': r['at'], 'records': f.get('records'), 'fileBytes': f['fileBytes']}
            break
    readers = [w for r in samples_wec for w in (r.get('windowsEventLog') or []) if start <= base.stamp(r['at']) < end]
    return {'linuxJobs': jobs(samples_linux), 'wecJobs': jobs(samples_wec), 'forwardedEventsFull': wrap,
            'wecReaderMaxima': {k: max((w.get(k) or 0 for w in readers), default=None) for k in ('gaps', 'resets', 'cursorConflicts', 'readErrors')},
            'deliveryFailureCodes': sorted({(r.get('delivery') or {}).get('lastFailureCode') for r in samples_linux + samples_wec
                                            if start <= base.stamp(r['at']) < end and r.get('delivery')} - {None}, key=str)}


def fault_outcomes(windows, alerts_result, restarts, latency):
    out = []
    excused = alerts_result['excusedByFault']
    for w in windows:
        executed = 'done' in w['steps'] and set(w['expectedHosts']) <= set(w['executedOn'])
        fired = {a['rule'] for a in excused if a['fault'] == w['id']}
        unresolved = [a for a in excused if a['fault'] == w['id'] and (not a['resolvedAt'] or stamp(a['resolvedAt']) > w['alertEnd'])]
        checks = {'executedOnEveryHost': executed, 'noFailedOrMissedStep': not w['errors'],
                  'startedWithin120s': w['lateSeconds'] is not None and w['lateSeconds'] <= 120,
                  'requiredAlertFired': not w['alertsRequiredAnyOf'] or bool(fired & set(w['alertsRequiredAnyOf'])),
                  'firedAlertsResolved': not unresolved}
        if w['kind'] == 'destination-outage':
            checks['restoredOnEveryHost'] = len(w['restores']) >= len(w['expectedHosts']) and all(r.get('restoredAt') for r in w['restores'])
            # Each host's block lasted the registered duration (one tick of tolerance), never cut short.
            checks['blockedForTheFullDuration'] = bool(w['restores']) and all(
                r.get('restoredAt') and stamp(r['restoredAt']) - w['start'] >= w['durationSeconds'] - 60 for r in w['restores'])
        if w['kind'] == 'host-reboot':
            checks['cameBackAfterReboot'] = len(w['afterReboot']) >= 1
        for host in w['collectors']:
            if host in restarts and host not in w['restarts']:
                checks['noRestart-' + host] = not any(u['kind'] == 'process' and w['start'] <= stamp(u['firstSeen']) <= w['impactEnd']
                                                      for u in restarts[host]['unexplained'])
        out.append({'fault': w['id'], 'kind': w['kind'], 'window': [base.iso(w['start']), base.iso(w['impactEnd'])],
                    'alertsFired': sorted(fired), 'maxLatencySeconds': {h: (latency.get(h, {}).get('perFault', {}).get(w['id']) or {}).get('max')
                                                                          for h in w['collectors']},
                    'checks': checks, 'pass': all(checks.values())})
    return out


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('fetch', 'smoke', 'interim', 'final'))
    parser.add_argument('--lab-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--cutoff', type=float)
    args = parser.parse_args()
    lab = args.lab_dir.resolve()
    if args.action == 'fetch':
        return fetch(lab)
    run = json.loads((lab / 'run.json').read_text())
    plan, plan_digest, registered = load_plan(lab, run)
    configure(run, plan)
    results = lab / 'results'
    cutoff = args.cutoff or dt.datetime.now(dt.timezone.utc).timestamp()
    verifier = base.Verifier(lab / 'azure')
    start, seconds = base.SOAK_START, base.SOAK_SECONDS
    end = start + seconds
    if args.action == 'smoke':
        scope_start, scope_end, label, windows_names = base.SMOKE_START, base.SMOKE_START + base.SMOKE_SECONDS + 60, 'smoke', ['smoke']
        minutes = (0, 0)
    elif args.action == 'interim':
        scope_start, scope_end, label, windows_names = start, start + 3600, 'soak', ['h00']
        minutes = (0, 60)
    else:
        scope_start, scope_end, label = start, end + 3600, 'soak'
        windows_names = base.profile('soak')['windows']
        minutes = (0, seconds // 60)
    records = fault_records(results)
    windows = fault_windows(plan, records, start) if label == 'soak' else []
    by_host = {h: [w for w in windows if h in w['collectors']] for h in ('linux', 'windows')}
    report = {'runId': run['runId'], 'scope': args.action, 'generatedAt': base.iso(dt.datetime.now(dt.timezone.utc).timestamp()),
              'planSha256': plan_digest, 'registeredPlanSha256': registered, 'dryRun': bool(plan.get('dryRun')),
              'window': [base.iso(scope_start), base.iso(scope_end)], 'ingestionCutoff': base.iso(cutoff),
              'verifierAppId': verifier.verifier['appId'], 'faultWindows': windows, 'collectors': {}}
    for host, (collector, event_type) in base.COLLECTORS.items():
        if host == 'linux':
            native, meta = base.firewall_native(results, label, start + 3630 if args.action == 'interim' else scope_end)
            prefix = max((base.index(i) for i in native), default=-1) if args.action == 'interim' else None
            union = base.accepted(results, host)
            queue = base.scope_accepted(host, union, label, prefix)
            canaries, canary_meta = firewall_canaries(results, *minutes)
            queue |= {i for i in union if CANARY_FIREWALL.fullmatch(i) and minutes[0] <= int(CANARY_FIREWALL.fullmatch(i).group(1)) - 20000 < minutes[1]}
            low, high = base.profile(label)['first'], base.profile(label)['first'] + base.profile(label)['events']
            top = high if args.action != 'interim' else min(high, prefix + 1)
            keep = lambda k, low=low, top=top: ((bool(FIREWALL_BULK.fullmatch(k)) and low <= base.index(k) < top)
                                                or (bool(CANARY_FIREWALL.fullmatch(k)) and minutes[0] <= int(k[10:]) - 20000 < minutes[1]))
            query_end = scope_end if args.action != 'interim' else start + 3900
        else:
            generator = base.dc_generator(results, label)
            canaries, canary_meta = windows_canaries(results, windows_names, *minutes)
            final = args.action != 'interim'
            native, meta = base.windows_native(results, windows_names, generator['attempted'] + canary_meta['ldap49'] if final else None)
            meta['generator'] = generator
            if final and (generator['segments'] != len(base.profile(label)['segments'])
                          or generator['attempted'] != base.profile(label)['events'] or not generator['allSegmentsClean']):
                meta['problems'].append('dc-generator-differs-from-profile')
                meta['complete'] = False
            union = base.accepted(results, host)
            queue = base.scope_accepted(host, union, label)
            if not final:
                queue = {i for i in queue if base.stamp_any(union[i]) < start + 3600 + 1800}
            keep, query_end = None, scope_end if final else start + 3600
        if label == 'soak' and args.action == 'final' and canary_meta.get('minutesWithoutCanary'):
            meta['problems'].append('canary-minutes-missing-%d' % canary_meta['minutesWithoutCanary'])
        native |= canaries if host == 'linux' else set()
        rows, hours, latency_all, hashes = base.sentinel(verifier, collector, event_type, scope_start - 120, query_end, cutoff, keep=keep)
        result = base.compare(native, queue, rows, meta['complete'] or args.action == 'interim')
        limit = base.LATENCY_P99_LIMIT[host]
        latency = latency_accounting(rows, by_host[host], limit)
        samples = base.load_samples(results / 'hosts' / ('linux' if host == 'linux' else 'wec') / 'samples.jsonl')
        result.update(nativeDetail=meta, canaries={**canary_meta, **canary_report(canaries, rows, by_host[host])},
                      hours=hours, latency=latency, queryHashes=hashes)
        if args.action == 'final':
            result['restarts'] = restarts_accounting(samples, host, by_host[host], start, end + 1800)
            result['growth'] = growth_accounting(samples, host, by_host[host], start, end)
            result['resources'] = base.resources(samples, host, start, end)
        report['collectors'][host] = result
    report['health'], _ = base.health(verifier, scope_start, scope_end)
    report['healthGaps'] = health_gaps(verifier, scope_start, scope_end, by_host)
    report['privacy'], report['privacyQueryHash'] = base.privacy(verifier, scope_start - 120, scope_end)
    report['alerts'] = base.alerts(verifier.state, scope_start, scope_end)
    report['alertAccounting'] = alerts_accounting(report['alerts'], windows, run['runId'])
    report['versions'] = versions(verifier, scope_start, scope_end)
    candidate = json.loads((lab / 'candidate.json').read_text())
    report['candidate'] = {k: candidate[k] for k in ('ciRun', 'buildNumber', 'commit', 'version', 'conclusion', 'jobsNotSucceeded', 'rpm', 'msi', 'signature')}
    report['versionMatches'] = bool(report['versions']) and all(v['Version'] == candidate['version'] for v in report['versions'])
    if args.action == 'final':
        report['naturalEvents'] = natural_events(base.load_samples(results / 'hosts' / 'linux' / 'samples.jsonl'),
                                                 base.load_samples(results / 'hosts' / 'wec' / 'samples.jsonl'), start, end)
        restarts = {h: c['restarts'] for h, c in report['collectors'].items()}
        report['faultOutcomes'] = fault_outcomes(windows, report['alertAccounting'],
                                                 restarts, {h: c['latency'] for h, c in report['collectors'].items()})
        privacy_ok = all(row['Matches'] == 0 for row in report['privacy']) and bool(report['privacy'])
        verdict = {}
        for host, c in report['collectors'].items():
            verdict[host] = {'1': c['exact'], '2': c['restarts']['pass'], '3': c['growth']['pass'], '4': c['latency']['pass'],
                             '5': report['alertAccounting']['pass'], '6': privacy_ok}
        report['verdict'] = {'criteria': verdict, 'faultOutcomesPass': all(f['pass'] for f in report['faultOutcomes']),
                             'versionMatches': report['versionMatches'],
                             'pass': all(all(v.values()) for v in verdict.values()) and all(f['pass'] for f in report['faultOutcomes'])
                             and report['versionMatches'] and not plan.get('dryRun')}
    text = json.dumps(report, indent=1, default=str)
    if args.out:
        args.out.write_text(text + '\n')
    summary = {h: {k: c.get(k) for k in ('native', 'accepted', 'sentinelDistinct', 'sentinelRows', 'duplicateRows', 'missingAtAccepted',
                                         'extraAtAccepted', 'missingAtSentinel', 'extraAtSentinel', 'nativeComplete', 'exact')}
               | {'latencyOutside': c['latency']['outsideFaultWindows'], 'canaries': {k: c['canaries'].get(k) for k in ('native', 'atSentinel', 'missing')},
                  'problems': c['nativeDetail']['problems']}
               for h, c in report['collectors'].items()}
    print(json.dumps({'scope': args.action, 'summary': summary, 'privacy': report['privacy'], 'alertAccounting': report['alertAccounting'],
                      'versions': report['versions'], 'verdict': report.get('verdict'),
                      'faults': [{k: w[k] for k in ('id', 'steps', 'executedOn', 'lateSeconds', 'errors')} for w in windows]}, indent=1, default=str))


if __name__ == '__main__':
    main()
