"""Bounded synthetic HTTP producer; records metadata and acknowledgements only."""
import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import subprocess
import threading
import time

ROOT=Path('/opt/bower-lab')
RUN=os.environ['BOWER_LAB_RUN']
HOST=os.environ['BOWER_LAB_HOST']
REGION=os.environ['AWS_DEFAULT_REGION']
BUCKET=os.environ['BOWER_LAB_BUCKET']
LOCAL=threading.local()


def aws(*args):
    output=subprocess.run(['aws','--region',REGION,*args,'--output','json'],check=True,capture_output=True,text=True).stdout
    return json.loads(output) if output.strip() else {}


def send(item):
    identity,payload,denied=item
    try:
        if not hasattr(LOCAL,'connection'):
            LOCAL.connection=http.client.HTTPConnection('127.0.0.1',4318 if HOST=='Collector' else 4319,timeout=10)
        start=time.monotonic()
        LOCAL.connection.request('POST','/v1/events',body=payload,headers={'Content-Type':'application/json'})
        response=LOCAL.connection.getresponse()
        body=response.read(65537)
        if len(body)>65536:
            raise ValueError('Oversized response')
        return identity,response.status,denied,time.monotonic()-start
    except Exception:
        if hasattr(LOCAL,'connection'):
            LOCAL.connection.close()
            del LOCAL.connection
        return identity,0,denied,0


def event(sequence,phase,deny_every,seed_every,corpus):
    identity=f'{RUN}-{HOST.lower()}-{phase}-{sequence}'
    denied=deny_every>0 and sequence%deny_every==0
    sensitive=seed_every>0 and sequence%seed_every==0
    reason='SyntheticFailure '+(' '.join(key+'='+value for key,value in corpus['values'].items()) if sensitive else 'negative-control-order-ABC123')
    payload={'schemaVersion':'1.0.0','eventId':identity,'eventOriginalId':identity,
        'timeGenerated':datetime.now(timezone.utc).isoformat(),'eventCategory':'authentication',
        'eventType':'unapproved_lab_noise' if denied else 'authentication_failure','eventAction':'authentication.attempt',
        'eventResult':'failure','eventOutcomeReason':reason,'application':{'name':'BowerLab','environment':'lab'},
        'actor':{'username':'synthetic-lab-operator'},'source':{'ipAddress':'192.0.2.10'},'request':{'correlationId':identity},
        'attributes':{'labPositiveControl':corpus['positiveControl']}}
    return identity,json.dumps(payload,separators=(',',':')).encode(),denied


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',required=True)
    parser.add_argument('--rate',type=int,default=50)
    parser.add_argument('--seconds',type=int,default=10)
    parser.add_argument('--count',type=int)
    parser.add_argument('--deny-every',type=int,default=0)
    parser.add_argument('--seed-every',type=int,default=10)
    args=parser.parse_args()
    if not args.phase.replace('-','').isalnum() or len(args.phase)>25 or not 1<=args.rate<=5000 or not 1<=args.seconds<=120:
        raise ValueError('Unbounded or invalid load configuration')
    limit=args.count if args.count is not None else args.rate*args.seconds
    if not 1<=limit<=600000:
        raise ValueError('Invalid event limit')
    corpus=json.loads(aws('secretsmanager','get-secret-value','--secret-id','bower-lab/'+RUN+'/corpus')['SecretString'])
    pending=set()
    outcomes={}
    acknowledged=[]
    denied_ids=[]
    unexpected=[]
    unexpected_statuses=0
    latencies=[]
    issued=0
    started=time.monotonic()
    def record(future):
        nonlocal unexpected_statuses
        identity,status,denied,latency=future.result()
        if status not in ((422,) if denied else (200,202)):
            unexpected_statuses+=1
        outcomes[str(status)]=outcomes.get(str(status),0)+1
        latencies.append(latency)
        if status in (200,202): acknowledged.append(identity)
        if denied: denied_ids.append(identity)
        if denied and status in (200,202): unexpected.append(identity)
    with ThreadPoolExecutor(max_workers=64) as pool:
        while issued<limit and time.monotonic()-started<args.seconds:
            target=min(limit,int((time.monotonic()-started)*args.rate)+1)
            while issued<target and len(pending)<64:
                issued+=1
                pending.add(pool.submit(send,event(issued,args.phase,args.deny_every,args.seed_every,corpus)))
            if pending:
                done,pending=wait(pending,timeout=0.002,return_when=FIRST_COMPLETED)
                for future in done: record(future)
            else:
                time.sleep(0.002)
        for future in pending: record(future)
    elapsed=time.monotonic()-started
    latencies.sort()
    report={'phase':args.phase,'host':HOST,'targetEps':args.rate,'durationSeconds':elapsed,'issued':issued,
        'acknowledged':len(acknowledged),'acknowledgedEps':len(acknowledged)/elapsed,'httpStatuses':outcomes,
        'producerP95Seconds':latencies[int((len(latencies)-1)*0.95)] if latencies else None,
        'unexpectedStatusCount':unexpected_statuses,'deniedInputCount':len(denied_ids),'unexpectedAccepted':len(unexpected),'sentinel':'deferred'}
    directory=ROOT/'results';directory.mkdir(exist_ok=True)
    (directory/(args.phase+'.acks.json')).write_text(json.dumps({'acknowledged':acknowledged,'denied':denied_ids}))
    (directory/(args.phase+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    for name in (args.phase+'.json',args.phase+'.acks.json'):
        subprocess.run(['aws','--region',REGION,'s3','cp',str(directory/name),'s3://'+BUCKET+'/runs/'+RUN+'/hosts/'+HOST+'/'+name,'--only-show-errors'],check=True,capture_output=True)
    print(json.dumps(report))
    if unexpected or unexpected_statuses:
        raise SystemExit(1)


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'phase':'load','host':HOST,'status':'failed','errorType':type(error).__name__}))
        raise SystemExit(1)
