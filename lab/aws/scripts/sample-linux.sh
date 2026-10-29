#!/bin/bash
set -euo pipefail
umask 077
python3 - <<'PY'
import json,os,pathlib,sqlite3,subprocess,time
samples=[]
for i in range(24):
    mem={line.split(':')[0]:int(line.split()[1]) for line in pathlib.Path('/proc/meminfo').read_text().splitlines()}
    c=sqlite3.connect('file:/var/lib/bower/queue.db?mode=ro',uri=True,timeout=2)
    states=dict(c.execute('SELECT state,count(*) FROM queue_events_v5 GROUP BY state'));c.close()
    disk=os.statvfs('/var/lib/bower')
    samples.append({'time':time.time(),'loadAverage':os.getloadavg(),'memoryUsedPercent':100*(1-mem['MemAvailable']/mem['MemTotal']),'queueStates':states,'diskAvailableBytes':disk.f_bavail*disk.f_frsize})
    time.sleep(5)
p=pathlib.Path('/opt/bower-lab/results/resources.json');p.write_text(json.dumps(samples))
subprocess.run(['aws','s3','cp',str(p),'s3://'+os.environ['BOWER_LAB_BUCKET']+'/runs/'+os.environ['BOWER_LAB_RUN']+'/hosts/'+os.environ['BOWER_LAB_HOST']+'/resources.json','--only-show-errors'],capture_output=True,check=True)
print(json.dumps({'host':os.environ['BOWER_LAB_HOST'],'samples':len(samples),'peakMemoryUsedPercent':max(s['memoryUsedPercent'] for s in samples)}))
PY
