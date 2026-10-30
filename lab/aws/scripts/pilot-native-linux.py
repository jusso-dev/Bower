#!/usr/bin/env python3
"""Disposable nftables-source pilot; reports metadata, never event payloads or tokens."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.request

ROOT = Path('/var/lib/bower-pilot')
QUEUE = Path('/var/lib/bower/queue.db')
OUTAGE_TABLE = 'bower_pilot_outage'


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def identity_rows(delivered_only=False):
    with sqlite3.connect('file:' + str(QUEUE) + '?mode=ro', uri=True) as db:
        where = ' where delivered_at is not null' if delivered_only else ''
        return {r[0] for r in db.execute('select event_id from queue_events' + where)}


def packet_count():
    rules = json.loads(command('nft', '-j', 'list', 'table', 'inet', 'bower_validation'))
    return sum(e['counter']['packets'] for item in rules['nftables'] if 'rule' in item
               for e in item['rule']['expr'] if 'counter' in e)


def generate(rate, seconds):
    # Only the disposable namespace can send, and only to its fixed local peer.
    code = '''import json,socket,sys,time
rate,seconds=map(int,sys.argv[1:])
assert 1<=rate<=100 and 1<=seconds<=3600
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
start=time.monotonic()
for i in range(rate*seconds):
 s.sendto(b"bower-pilot",("172.19.0.1",4444))
 time.sleep(max(0,start+(i+1)/rate-time.monotonic()))
elapsed=time.monotonic()-start
print(json.dumps({"sent":rate*seconds,"seconds":elapsed,"actualRate":rate*seconds/elapsed}))
'''
    result = subprocess.run(['ip', 'netns', 'exec', 'bower-client', 'python3', '-c', code,
                             str(rate), str(seconds)], capture_output=True, text=True,
                            timeout=seconds + 30, check=True)
    return json.loads(result.stdout)


def qualification_checks(*, failure, phases, sent, native, accepted, outage_seconds,
                         backlog, drain_seconds, dead_letters, all_acknowledged,
                         integrity, sampling_errors):
    """Fail closed on source loss, insufficient outage and incomplete measurements."""
    return {'completed':failure is None and len(phases)==5,
            'generatedAtTargetRate':bool(phases) and all(p['actualRate']>=p['rate']*.99 for p in phases),
            'nativePacketCount':sent>0 and native==sent,'noSourceLoss':sent>0 and accepted==sent,
            'outageAtLeastOneHour':outage_seconds>=3600,'backlogRetained':backlog>=41400,
            'backlogDrainedWithinTenMinutes':drain_seconds is not None and 0<=drain_seconds<=600,
            'noDeadLetters':dead_letters==0,'allAcceptedAcknowledged':all_acknowledged,
            'sqliteIntegrity':integrity,'samplingSucceeded':not sampling_errors}


def wait_for_population(expected_accepted, settle_seconds=30):
    """Wait for sender flush as well as delivery; an empty partial queue is not done."""
    for attempt in range(settle_seconds + 1):
        accepted = identity_rows()
        if len(accepted) == expected_accepted and accepted == identity_rows(True):
            return True
        if attempt < settle_seconds:
            time.sleep(1)
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'bower-pilot-\d{8}-\d{6}', args.run_id) or os.geteuid() != 0:
        raise RuntimeError('Requires an owned disposable pilot host and root')
    if command('systemctl', 'show', 'bower', '--property=User', '--value') != 'bower':
        raise RuntimeError('Unexpected collector service account')
    packet_count()  # Refuse to operate without the dedicated source namespace/table.
    existing = subprocess.run(['nft', 'list', 'table', 'inet', OUTAGE_TABLE], capture_output=True)
    if existing.returncode == 0:
        raise RuntimeError('Outage table already exists; refusing to replace it')
    ROOT.mkdir(mode=0o700, exist_ok=True)
    os.umask(0o077)
    token = Path('/etc/bower/secrets/token').read_text().strip()
    headers = {'Authorization': 'Bearer ' + token}
    start = time.monotonic()
    samples = []
    sampling_errors = []
    phase = 'starting'
    backlog = set()
    restored = None
    drained = None
    stopped = threading.Event()
    prior_cpu = None

    def sample():
        nonlocal prior_cpu, drained
        request = urllib.request.Request('http://127.0.0.1:4319/v1/status', headers=headers)
        with urllib.request.urlopen(request, timeout=10) as response:
            status = json.load(response)
        pid = int(command('systemctl', 'show', 'bower', '--property=MainPID', '--value'))
        stat = Path('/proc/' + str(pid) + '/stat').read_text().split()
        cpu = (int(stat[13]) + int(stat[14])) / os.sysconf('SC_CLK_TCK')
        now = time.monotonic()
        cpu_percent = 0 if prior_cpu is None else 100 * (cpu - prior_cpu[1]) / (now - prior_cpu[0])
        prior_cpu = (now, cpu)
        resident = int(Path('/proc/' + str(pid) + '/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
        queue = status['queue']
        accepted = sum(queue[k] for k in ['queued', 'retrying', 'uploading', 'delivered', 'deadLettered'])
        pending = accepted - queue['delivered']
        if restored is not None and drained is None and not (backlog - identity_rows(True)):
            drained = {'at': utc(), 'secondsAfterRestore': round(now - restored, 3)}
        record = [round(now-start, 2), phase, accepted, pending, queue['deadLettered'],
                  round(cpu_percent, 2), resident, shutil.disk_usage(QUEUE.parent).free,
                  sum(p.stat().st_size for p in QUEUE.parent.glob('queue.db*'))]
        samples.append(record)
        (ROOT/'progress.json').write_text(json.dumps({'runId':args.run_id,'utc':utc(),
            'sample':record,'drain':drained,'samplingErrors':len(sampling_errors)}))
        if record[7] < 512*1024*1024:
            sampling_errors.append('low-free-disk')

    def sampler():
        while not stopped.is_set():
            try:
                sample()
            except Exception as error:
                sampling_errors.append(type(error).__name__)
            stopped.wait(5)

    initial_ids = identity_rows()
    initial_packets = packet_count()
    phases = []
    report = {'runId':args.run_id,'phase':'native-linux-pilot','startedAt':utc(),
              'initialAccepted':len(initial_ids),'initialPackets':initial_packets}
    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    outage_created = False
    failure = None
    try:
        for name, rate, seconds in [('steady',10,600),('burst',100,60)]:
            phase = name
            phases.append({'name':name,'rate':rate,**generate(rate,seconds)})
        phase = 'outage'
        uid = int(command('id','-u','bower'))
        rule = ('table inet '+OUTAGE_TABLE+' { chain output { type filter hook output priority -10; '
                'policy accept; meta skuid '+str(uid)+' tcp dport 443 reject; }; }\n')
        subprocess.run(['nft','-f','-'], input=rule, text=True, check=True)
        outage_created = True
        outage_start = time.monotonic()
        report['outageStartedAt'] = utc()
        for name, rate, seconds in [('outage-burst',100,60),('outage-steady',10,3540)]:
            phases.append({'name':name,'rate':rate,**generate(rate,seconds)})
        # Capture the exact durable backlog before restoring the destination.
        backlog = identity_rows() - identity_rows(True)
        report['backlogAtRestore'] = len(backlog)
        report['outageSeconds'] = time.monotonic()-outage_start
        subprocess.run(['nft','delete','table','inet',OUTAGE_TABLE], check=True)
        outage_created = False
        restored = time.monotonic()
        report['restoredAt'] = utc()
        phase = 'drain-with-live-traffic'
        phases.append({'name':phase,'rate':10,**generate(10,600)})
        phase = 'settle-final-live-events'
        expected_accepted = len(initial_ids) + sum(p['sent'] for p in phases)
        wait_for_population(expected_accepted)
    except Exception as error:
        failure = type(error).__name__
    finally:
        if outage_created:
            subprocess.run(['nft','delete','table','inet',OUTAGE_TABLE], check=True)
        stopped.set()
        thread.join(timeout=15)
    phase = 'complete'
    sample()
    final_ids = identity_rows()
    delivered_ids = identity_rows(True)
    sent = sum(p['sent'] for p in phases)
    native = packet_count()-initial_packets
    with sqlite3.connect('file:'+str(QUEUE)+'?mode=ro',uri=True) as db:
        integrity = db.execute('pragma integrity_check').fetchone()[0]=='ok'
    checks = qualification_checks(failure=failure,phases=phases,sent=sent,native=native,
        accepted=len(final_ids-initial_ids),outage_seconds=report.get('outageSeconds',0),
        backlog=report.get('backlogAtRestore',0),drain_seconds=None if drained is None else drained['secondsAfterRestore'],
        dead_letters=max(s[4] for s in samples),all_acknowledged=final_ids==delivered_ids,
        integrity=integrity,sampling_errors=sampling_errors)
    report.update({'endedAt':utc(),'phases':phases,'checks':checks,'passed':all(checks.values()),
        'failureType':failure,'samplingErrors':sampling_errors,'generated':sent,'nativePackets':native,
        'finalAccepted':len(final_ids),'finalDelivered':len(delivered_ids),'drain':drained,
        'identitySetSha256':hashlib.sha256('\n'.join(sorted(final_ids)).encode()).hexdigest(),
        'peakCollectorCpuPercentOfOneCore':max(s[5] for s in samples),'peakCollectorResidentBytes':max(s[6] for s in samples),
        'minimumFreeDiskBytes':min(s[7] for s in samples),'maximumDbWalBytes':max(s[8] for s in samples),
        'sampleColumns':['elapsedSeconds','phase','accepted','pending','deadLetters','cpuPercentOfOneCore','rssBytes','freeDiskBytes','dbWalBytes'],
        'samples':samples[::12]+samples[-1:]})
    (ROOT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,separators=(',',':')))


if __name__ == '__main__':
    main()
