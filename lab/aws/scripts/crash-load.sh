#!/bin/bash
set -euo pipefail
umask 077
python3 - <<'PY'
import json,subprocess,time,urllib.request,os
from pathlib import Path
root=Path('/opt/bower-lab/results')
with (root/'crash-producer.log').open('w') as output:
    producer=subprocess.Popen(['python3','/opt/bower-lab/load.py','--phase','crash','--rate','50','--seconds','30'],stdout=output,stderr=subprocess.DEVNULL)
    time.sleep(5)
    crashed_at=time.time()
    start=time.monotonic()
    subprocess.run(['systemctl','kill','--kill-whom=main','--signal=SIGKILL','bower'],check=True,capture_output=True)
    healthy=False
    while time.monotonic()-start<120:
        try:
            with urllib.request.urlopen('http://127.0.0.1:'+('4318' if os.environ['BOWER_LAB_HOST']=='Collector' else '4319')+'/health',timeout=2) as response:healthy=response.status==200
            if healthy:break
        except Exception:pass
        time.sleep(1)
    recovery=time.monotonic()-start
    producer.wait(timeout=60)
report={'phase':'crash','host':os.environ['BOWER_LAB_HOST'],'healthy':healthy,'recoverySeconds':recovery,'producerExitCode':producer.returncode,'crashedAtUnix':crashed_at,'recoveryDeadlineSeconds':120}
p=root/'crash-recovery.json';p.write_text(json.dumps(report))
subprocess.run(['aws','s3','cp',str(p),'s3://'+os.environ['BOWER_LAB_BUCKET']+'/runs/'+os.environ['BOWER_LAB_RUN']+'/hosts/'+os.environ['BOWER_LAB_HOST']+'/crash-recovery.json','--only-show-errors'],capture_output=True,check=True)
print(json.dumps(report))
if not healthy:raise SystemExit(1)
PY
