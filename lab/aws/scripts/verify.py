"""Verify metadata-only receipts against local durable output; never export event bodies."""
import argparse
from collections import Counter
from datetime import datetime
import json
import math
import os
import re
from pathlib import Path
import sqlite3
import subprocess
import time

ROOT=Path('/opt/bower-lab')
RUN=os.environ['BOWER_LAB_RUN']
REGION=os.environ['AWS_DEFAULT_REGION']
BUCKET=os.environ['BOWER_LAB_BUCKET']

def aws(*args):
    p=subprocess.run(['aws','--region',REGION,*args,'--output','json'],capture_output=True,text=True,check=True)
    return json.loads(p.stdout) if p.stdout.strip() else {}

def get_json(key):
    # Reports contain IDs/counts only. The corpus is fetched separately in memory.
    p=ROOT/'receipts'/Path(key).name
    p.parent.mkdir(exist_ok=True)
    subprocess.run(['aws','--region',REGION,'s3','cp','s3://'+BUCKET+'/'+key,str(p),'--only-show-errors'],capture_output=True,check=True)
    return json.loads(p.read_text())

def snapshot():
    events=Counter(); correlations=Counter(); positive=0; negative=0; detectors=Counter(); latencies=[]; leaks=Counter()
    output_times={}
    corpus=json.loads(aws('secretsmanager','get-secret-value','--secret-id','bower-lab/'+RUN+'/corpus')['SecretString'])
    for path in Path('/var/lib/bower/spool/ready').glob('*.jsonl'):
        with path.open() as stream:
            for line in stream:
                event=json.loads(line)
                events[event['eventId']]+=1
                identity=event['eventId']
                output_times[identity]=min(output_times.get(identity,float('inf')),path.stat().st_mtime)
                correlation=event.get('request',{}).get('correlationId')
                # Privacy alerts intentionally inherit correlation IDs; they are distinct events.
                if correlation and event['eventType']=='authentication_failure': correlations[correlation]+=1
                positive+=event.get('attributes',{}).get('labPositiveControl')==corpus['positiveControl']
                negative+='negative-control-order-ABC123' in event.get('eventOutcomeReason','')
                for name,value in corpus['values'].items():
                    leaks[name]+=line.count(value)
                detected=event.get('privacy',{}).get('detected',[])
                for value in detected:
                    if isinstance(value,str): detectors[value]+=1
                    elif isinstance(value,dict): detectors[value.get('detectorId','unknown')]+=1
                timestamp=event.get('timeGenerated')
                if timestamp:
                    latencies.append(max(0,path.stat().st_mtime-datetime.fromisoformat(re.sub(r'\.(\d+)', lambda m: '.'+m[1][:6].ljust(6,'0'), timestamp.replace('Z','+00:00'))).timestamp()))
    return events,correlations,positive,negative,detectors,latencies,leaks,corpus,output_times

def receipt_summary(receipts,events,correlations,output_times=None,enforce_deadline=False):
    rows=[]
    for host,name,receipt in receipts:
        expected=receipt.get("acknowledged",receipt.get("correlations",[]))
        observed=events if "acknowledged" in receipt else correlations
        cutoff=receipt.get('recoveryDeadlineUnix') if enforce_deadline and name=='crash.acks.json' else None
        late=set()
        if cutoff is not None:
            late={identity for identity in expected if observed[identity] and (output_times or {}).get(identity,float('inf'))>cutoff}
        rows.append({"host":host,"phase":name,"expected":len(expected),"missing":sum(observed[x]==0 or x in late for x in expected),
            "duplicates":sum(max(0,observed[x]-1) for x in expected),"deniedInOutput":sum(events[x] for x in receipt.get("denied",[]))})
        if cutoff is not None:
            rows[-1].update(recoveryDeadlineUnix=cutoff,recoveryDeadlineSeconds=receipt['recoveryDeadlineSeconds'],arrivedAfterDeadline=len(late))
    return rows


def crash_deadline(receipts):
    crashes={host:receipt for host,name,receipt in receipts if name=='crash.acks.json'}
    if set(crashes)!={'Collector','Linux1','Linux2'}:
        raise ValueError('Final deadline check requires all three Linux crash receipts')
    for receipt in crashes.values():
        cutoff=receipt.get('recoveryDeadlineUnix')
        if not isinstance(cutoff,(int,float)) or not math.isfinite(cutoff) or cutoff<=0 or cutoff>time.time()+120 or receipt.get('recoveryDeadlineSeconds')!=120:
            raise ValueError('Final deadline check requires recorded crash timestamps')
    return max(receipt['recoveryDeadlineUnix'] for receipt in crashes.values())

def consistency_passed(rows,events,integrity,*leak_counts):
    return bool(rows) and integrity and not any(r["missing"] or r["duplicates"] or r["deniedInOutput"] for r in rows) and not any(v>1 for v in events.values()) and not any(any(counts.values()) for counts in leak_counts)

def validate_receipts(receipts):
    required={'Collector','Linux1','Linux2','Wec','Windows1','Windows2'}
    populated=set()
    for host,_,receipt in receipts:
        expected=receipt.get('acknowledged',receipt.get('correlations',[]))
        if len(expected)!=len(set(expected)):
            raise ValueError('Duplicate IDs in a source receipt')
        if 'correlations' in receipt and receipt.get('written')!=len(expected):
            raise ValueError('Native receipt does not match source write count')
        if expected:populated.add(host)
    if {host for host,_,_ in receipts}!=required or populated!=required:
        raise ValueError('Missing or empty source receipts')

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',required=True)
    parser.add_argument('--wait-seconds',type=int,default=120)
    args=parser.parse_args()
    if not args.phase.replace('-','').isalnum() or not 0<=args.wait_seconds<=120: raise ValueError('Invalid bounds')
    receipts=get_json('artifacts/receipts.json')
    validate_receipts(receipts)
    deadline=crash_deadline(receipts) if args.phase=='final' else None
    started=time.monotonic()
    while True:
        events,correlations,positive,negative,detectors,latencies,leaks,corpus,output_times=snapshot()
        rows=receipt_summary(receipts,events,correlations,output_times,enforce_deadline=deadline is not None)
        finished=time.time()>=deadline if deadline is not None else time.monotonic()-started>=args.wait_seconds
        if not any(r['missing'] for r in rows) or finished: break
        time.sleep(2)
    # Scan persisted collector files without uploading any data. Raw source logs are deliberately excluded.
    stored_hits=Counter()
    values={name:value.encode() for name,value in corpus['values'].items()}
    overlap=max(map(len,values.values()))-1
    for path in Path('/var/lib/bower').rglob('*'):
        if not path.is_file() or 'spool' in path.parts or path.name=='.lab-disk-fill': continue
        tail=b''
        with path.open('rb') as stream:
            while True:
                chunk=stream.read(1024*1024)
                if not chunk: break
                data=tail+chunk
                for name,value in values.items(): stored_hits[name]+=data.count(value)-tail.count(value)
                tail=data[-overlap:]
    journal=subprocess.run(['journalctl','-u','bower','--no-pager','-o','cat'],capture_output=True,check=True).stdout
    log_hits={name:journal.count(value) for name,value in values.items()}
    database=sqlite3.connect('file:/var/lib/bower/queue.db?mode=ro',uri=True)
    integrity=database.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; database.close()
    latencies.sort()
    report={'phase':args.phase,'timingBasis':'recorded-crash-cutoff' if deadline is not None else 'verification-window','sentinel':'deferred','destination':'local-ama-spool','scope':'delivery-consistency-and-redaction; performance-scored-separately','receipts':rows,
        'outputRows':sum(events.values()),'uniqueEvents':len(events),'duplicateOutputEvents':sum(v-1 for v in events.values()),
        'positiveControls':positive,'negativeControls':negative,'detectedLabels':dict(detectors),'rawSeedHits':dict(leaks),
        'persistedRawSeedHits':dict(stored_hits),'serviceLogRawSeedHits':log_hits,'sqliteIntegrity':integrity,
        'observedDrainWaitSeconds':time.monotonic()-started,
        'outputLatencyP95Seconds':latencies[int((len(latencies)-1)*.95)] if latencies else None}
    passed=consistency_passed(rows,events,integrity,leaks,stored_hits,log_hits)
    report['status']='passed' if passed else 'failed'
    path=ROOT/(args.phase+'-verification.json');path.write_text(json.dumps(report,indent=2)+'\n')
    subprocess.run(['aws','--region',REGION,'s3','cp',str(path),'s3://'+BUCKET+'/runs/'+RUN+'/verification/'+path.name,'--only-show-errors'],capture_output=True,check=True)
    print(json.dumps(report))
    if not passed: raise SystemExit(1)

if __name__=='__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'phase':'verification','status':'failed','errorType':type(error).__name__}))
        raise SystemExit(1)
