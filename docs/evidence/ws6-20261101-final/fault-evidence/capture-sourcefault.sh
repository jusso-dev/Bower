#!/usr/bin/env bash
# Read-only, allowlisted fault and host metadata. Never emit journal bodies.
set -euo pipefail
umask 077
python3 - <<'PY'
import datetime as dt, hashlib, json, math, os, re, subprocess
from pathlib import Path
run=os.environ['BOWER_LAB_RUN']; scenario=os.environ['BOWER_SCENARIO']; unit=os.environ['BOWER_FAULT_UNIT']; action=os.environ['BOWER_FAULT_ACTION']; mode=os.environ['BOWER_CAPTURE_MODE']
since=float(os.environ['BOWER_SCOPE_START_EPOCH']); until=float(os.environ['BOWER_SCOPE_END_EPOCH'])
assert re.fullmatch(r'bower-ws6-\d{8}-\d{6}',run) and re.fullmatch(r'[ab]-[a-z-]+',scenario)
assert re.fullmatch(r'bower-lab-f-[a-z0-9-]+',unit) and action in ('restart','kill','blackhole','reset','reboot','stop-start')
assert mode in ('before','after') and math.isfinite(since) and math.isfinite(until) and 0<until-since<8000

def call(*args):
 return subprocess.run(args,capture_output=True,text=True,timeout=30)

def utc(value):
 assert isinstance(value,str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)',value)
 return dt.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()

services={}
for name in ('bower','rsyslog'):
 response=call('systemctl','show',name,'--property=MainPID,ActiveState,SubState,NRestarts,ExecMainStartTimestampMonotonic')
 fields={line.split('=',1)[0]:line.split('=',1)[1] for line in response.stdout.splitlines() if '=' in line}
 selected={}
 for key in ('MainPID','NRestarts','ExecMainStartTimestampMonotonic'):
  value=fields.get(key,'0'); assert re.fullmatch(r'\d{1,20}',value); selected[key]=int(value)
 for key in ('ActiveState','SubState'):
  value=fields.get(key,'unknown'); assert re.fullmatch(r'[a-z-]{1,32}',value); selected[key]=value
 pid=selected['MainPID']
 if pid:
  stat=Path('/proc/'+str(pid)+'/stat').read_text(); selected['startTicks']=int(stat[stat.rfind(')')+2:].split()[19])
 services[name]=selected
report={'schemaVersion':1,'runId':run,'scenario':scenario,'unit':unit,'action':action,'mode':mode,'observedAt':dt.datetime.now(dt.timezone.utc).isoformat(),'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'services':services,'faultRecords':[],'deliveryQualified':False}
assert re.fullmatch(r'[a-f0-9-]{36}',report['bootId'])
if mode=='after':
 response=call('journalctl','-u',unit+'.service','--since','@'+str(since),'--until','@'+str(until),'--output=cat','--no-pager','--lines=512')
 assert response.returncode==0 and len(response.stdout.encode())<=131072
 text=response.stdout; decoder=json.JSONDecoder(); candidates=[]
 for match in re.finditer(r'\{',text):
  try: record,_=decoder.raw_decode(text[match.start():])
  except ValueError: continue
  if isinstance(record,dict) and record.get('fault')==action:
   assert since<=utc(record['startedAt'])<=utc(record['endedAt'])<=until
   row={key:record[key] for key in ('fault','startedAt','endedAt','duration')}
   assert type(row['duration']) in (int,float) and 0<=row['duration']<=3600
   if 'killedPid' in record:
    assert type(record['killedPid']) is int and record['killedPid']>0; row['killedPid']=record['killedPid']
   if 'packets' in record:
    assert type(record['packets']) is int and record['packets']>=0; row['packetCount']=record['packets']
   candidates.append(row)
 assert len(candidates)<=1
 report['faultRecords']=candidates
 marker=Path('/var/lib/bower-lab/reboot-requested')
 if action=='reboot' and marker.is_file():
  value=marker.read_text().strip(); assert since<=utc(value)<=until; report['rebootRequestedAt']=value
 report['faultCompletionRecorded']=len(candidates)==1
report['installedSourceSha256']=hashlib.sha256(Path('/opt/bower-lab/syslog-host.py').read_bytes()).hexdigest()
encoded=json.dumps(report); assert len(encoded.encode())<=16384
print(encoded)
PY
