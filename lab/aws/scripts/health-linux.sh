#!/bin/bash
set -euo pipefail
python3 - <<'PY'
import json,os,time,urllib.request
from pathlib import Path
port=4318 if os.environ['BOWER_LAB_HOST']=='Collector' else 4319
with urllib.request.urlopen('http://127.0.0.1:'+str(port)+'/health',timeout=5) as response:health=json.load(response)
print(json.dumps({'phase':'post-reboot','host':os.environ['BOWER_LAB_HOST'],'bootTime':time.time()-float(Path('/proc/uptime').read_text().split()[0]),'health':health['status']}))
PY
