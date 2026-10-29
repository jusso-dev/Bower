"""Build a scorecard from downloaded metadata-only reports; never ingest seed manifests."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import math
from pathlib import Path


def build(root,state,manifest,thresholds):
    read=lambda path:json.loads((root/path).read_text())
    final=read('verification/final-drained-verification.json')
    baseline=read('verification/baseline-drained-verification.json')
    timed=read('verification/final-verification.json')
    p0=read('P0/fleet.json')
    metadata=read('ssm-metadata.json')
    windows={}
    windows_ledgers={}
    for command in metadata:
        for entry in command['metadata']:
            if entry.get('phase')=='post-reboot' and entry.get('health')=='healthy' and entry.get('host') in ('Wec','Windows1','Windows2'):windows[entry['host']]=entry
            if entry.get('phase')=='ledger':windows_ledgers[entry['host']]=entry
    claims=[]
    def claim(name,value,limit,passed,scope):
        claims.append({'claim':name,'measured':value,'threshold':limit,'status':'passed' if passed else 'failed','scope':scope})
    missing=sum(r['missing'] for r in final['receipts'])
    claim('Acknowledged/source-event loss after eventual drain',missing,0,missing==0,'HTTP acknowledgements and native Windows correlations in this run')
    claim('Duplicate output event IDs',final['duplicateOutputEvents'],0,final['duplicateOutputEvents']==0,'All local AMA spool rows, including derived privacy alerts')
    denied=sum(r['deniedInOutput'] for r in final['receipts'])
    claim('Denied events in output',denied,0,denied==0,'Unapproved HTTP source events listed in producer receipts')
    leaks=sum(sum(final[key].values()) for key in ('rawSeedHits','persistedRawSeedHits','serviceLogRawSeedHits'))
    claim('Raw synthetic seed leaks',leaks,0,leaks==0,'Central ready spool, non-spool persisted state and service journal only; original source logs and seed manifest excluded')
    ledgers={host:read('hosts/'+host+'/ledger.json') for host in ('Collector','Linux1','Linux2')}
    ledgers.update(windows_ledgers)
    intact=sum(r.get('intact') is True for r in ledgers.values())
    claim('Queue ledgers intact',intact,6,intact==6,'All six collectors after faults/reboots')
    claim('Remote administration and invalid assertion denied',p0['negativeAuth'],{'anonymous-admin':401,'invalid-assertion':401,'remote-dashboard':403},p0['status']=='passed','Ephemeral TLS proxy; isolated development administration, not production Entra login')
    latency=baseline['outputLatencyP95Seconds']
    claim('Load output p95 latency seconds',latency,thresholds['normalOutputP95LatencySeconds'],latency<=thresholds['normalOutputP95LatencySeconds'],'Event timestamp to local spool file publication; not Sentinel ingestion')
    outage=read('hosts/Collector/outage-recovery.json')
    claim('Relay outage drain seconds',outage['recoverySeconds'],thresholds['recoveryDeadlineSeconds'],outage['status']=='passed','Accepted source events buffered by two Linux edges during the relay stop')
    crash={host:read('hosts/'+host+'/crash-recovery.json') for host in ('Collector','Linux1','Linux2')}
    health=max(r['recoverySeconds'] for r in crash.values())
    claim('SIGKILL process health recovery seconds',health,thresholds['recoveryDeadlineSeconds'],all(r['healthy'] for r in crash.values()) and health<=thresholds['recoveryDeadlineSeconds'],'Three Linux collectors under HTTP load; transport errors during downtime are recorded separately')
    delayed=sum(r['missing'] for r in timed['receipts'] if r['phase']=='crash.acks.json')
    claim('Acknowledged events still pending after crash drain deadline',delayed,0,delayed==0,f'{delayed} acknowledged events pending or late in the saved deadline check; eventual delivery is scored separately')
    timings=[r.get('bootToProcessSeconds') for r in windows.values()]
    valid_timings=len(timings)==3 and all(isinstance(t,(int,float)) and not isinstance(t,bool) and math.isfinite(t) and t>=0 for t in timings)
    win=max(timings) if valid_timings else None
    claim('Windows boot-to-process seconds',win,thresholds['recoveryDeadlineSeconds'],valid_timings and win<=thresholds['recoveryDeadlineSeconds'],'Delayed automatic startup; health was verified after startup, so this is a lower bound on recovery')
    disk=read('hosts/Collector/disk.json')
    claim('Disk-full returns back-pressure',disk['httpStatuses'],'503 with no unexpected errors',disk['status']=='passed','Only the isolated 4GiB queue volume; fill removed in finally and by an independent timer')
    replay=read('hosts/Collector/replay.json')
    claim('Replay semantics',[replay['first'],replay['identical'],replay['conflicting']],[202,200,409],replay['status']=='passed','One byte-identical replay and one conflicting identity')
    load=[]
    for phase,target in [('load1k',1000),('load5k',5000)]:
        sources=[read('hosts/'+host+'/'+phase+'.json') for host in ('Linux1','Linux2')]
        load.append({'phase':phase,'aggregateTargetEps':target,'accepted':sum(s['acknowledged'] for s in sources),'sumPerSourceAcceptedEps':sum(s['acknowledgedEps'] for s in sources),'sourceReports':sources,'status':'exploratory-target-met' if sum(s['acknowledgedEps'] for s in sources)>=target else 'exploratory-below-target','note':'Compare achieved rate with the requested target. Bounded generator concurrency may limit offered rate; this does not isolate collector-only capacity.'})
    resource=[]
    for host in ('Collector','Linux1','Linux2'):
        samples=read('hosts/'+host+'/resources.json')
        resource.append({'host':host,'sampleCount':len(samples),'peakMemoryUsedPercent':max(s['memoryUsedPercent'] for s in samples),'peakOneMinuteLoad':max(s['loadAverage'][0] for s in samples),'minimumDiskAvailableBytes':min(s['diskAvailableBytes'] for s in samples)})
    findings=[]
    if latency>thresholds['normalOutputP95LatencySeconds'] or any(step['status']=='exploratory-below-target' for step in load):
        findings.append('https://github.com/jusso-dev/Bower/issues/153')
    if delayed or not valid_timings or win>thresholds['recoveryDeadlineSeconds']:
        findings.append('https://github.com/jusso-dev/Bower/issues/154')
    cleanup=read('cleanup.json') if (root/'cleanup.json').exists() else {'status':'pending'}
    return {'schemaVersion':'1.0','runId':state['runId'],'generatedAt':datetime.now(timezone.utc).isoformat(),'status':'failed' if any(c['status']=='failed' for c in claims) or cleanup['status']=='failed' else ('passed' if cleanup['status']=='passed' else 'incomplete'),
        'scope':'Short AWS multi-node validation to local AMA spool; incomplete issue 136 suite','sentinel':'deferred-by-user','azureResourcesCreated':False,
        'version':manifest['version'],'sourceCommit':manifest['sourceCommit'],'artifactCommit':manifest['artifactCommit'],'artifactRun':manifest['artifactRun'],'artifactHashes':manifest['files'],
        'region':state['region'],'linuxCollectors':3,'windowsCollectors':3,'controlHosts':1,'linuxType':'t3.micro','windowsFallback':state['windowsFallback'],'cpuCredits':state['cpuCredits'],
        'expectedSourceEvents':sum(r['expected'] for r in final['receipts']),'outputRowsIncludingPrivacyAlerts':final['outputRows'],'uniqueOutputEvents':final['uniqueEvents'],
        'unacknowledgedSourceEventsAlsoObserved':final['positiveControls']-sum(r['expected'] for r in final['receipts'] if r['phase'].endswith('.acks.json')),
        'claims':claims,'load':load,'resources':resource,'processCrash':crash,'windowsReboot':windows,'receiptSummary':final['receipts'],'detectedLabels':final['detectedLabels'],
        'dashboard':read('dashboard-browser.json'),'cleanup':cleanup,'reports':'s3://'+state['outputs']['Bucket']+'/runs/'+state['runId']+'/',
        'findings':findings,
        'limits':['Sentinel destination/query verification deferred; no Azure resources touched','Wec is a role name: local Windows Application subscriptions tested, not real WEF/WEC or original Computer preservation','Linux inputs were semantic HTTP events, not native journald/auditd/syslog','Only four synthetic detector families and one benign control; no complete adversarial privacy corpus','Central persisted-state/log scan only; edge state/log redaction scans not performed','60-second load steps; no 30-minute steps, burst campaign or long soak','Development loopback administration tested, not production Entra interactive authentication','Artifact hashes and commits identify the packages; package-signing status is not verified by this scorer','No upgrade, uninstall, full power-loss, tamper, packet-loss, credential-rotation or bad-policy-push campaign','No AWS Budget alarm; independent expiry guard and explicit audited teardown used']}


def summary(report):
    failed=[claim['claim'] for claim in report['claims'] if claim['status']=='failed']
    parts=['Overall: **'+report['status'].upper()+'**.']
    parts.append('Failed checks: '+', '.join(failed)+'.' if failed else 'All measured claims passed.')
    if report['cleanup']['status']!='passed':
        parts.append('Cleanup is '+report['cleanup']['status']+'.')
    return ' '.join(parts)


def markdown_lines(report):
    lines=['# AWS lab '+report['runId'],'',summary(report),'',
        'Sentinel verification was deferred. This is a short local-output AWS run, not completion of #136.','',
        '| Check | Result | Measured | Threshold |','| --- | --- | --- | --- |']
    for c in report['claims']:lines.append('| '+c['claim']+' | '+c['status']+' | '+json.dumps(c['measured'])+' | '+json.dumps(c['threshold'])+' |')
    lines.extend(['','## Coverage limits','']+['- '+line for line in report['limits']])
    lines.extend(['','## Artifacts','',report['reports'],'','Findings: '+', '.join(report['findings']), '', 'Cleanup: '+report['cleanup']['status']+'.'])
    return lines

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--state',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--thresholds',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report=build(a.input,json.loads(a.state.read_text()),json.loads(a.manifest.read_text()),json.loads(a.thresholds.read_text()))
    report['thresholdsSha256']=hashlib.sha256(a.thresholds.read_bytes()).hexdigest()
    a.output.mkdir(parents=True,exist_ok=True);target=a.output/'report.json';target.write_text(json.dumps(report,indent=2)+'\n')
    lines=markdown_lines(report)
    (a.output/'report.md').write_text('\n'.join(lines)+'\n')
    (a.output/'SHA256SUMS').write_text(''.join(hashlib.sha256((a.output/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in ('report.json','report.md')))
    print(json.dumps({'status':report['status'],'expectedSourceEvents':report['expectedSourceEvents'],'failedClaims':[c['claim'] for c in report['claims'] if c['status']=='failed'],'cleanup':report['cleanup']['status']}))

if __name__=='__main__':main()
