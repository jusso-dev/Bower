#!/bin/bash
set -euo pipefail
umask 077
# Native CLI from the same recorded artifact manifest, no credentials in arguments.
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/cli.tar.gz" /opt/bower-lab/cli.tar.gz --only-show-errors
python3 - <<'PY'
import hashlib,json,os,subprocess,tarfile
from pathlib import Path
root=Path('/opt/bower-lab');manifest=json.loads((root/'manifest.json').read_text())
archive=root/'cli.tar.gz'
if hashlib.sha256(archive.read_bytes()).hexdigest()!=manifest['files']['cli.tar.gz']:raise ValueError('CLI hash mismatch')
destination=root/'cli';destination.mkdir(exist_ok=True)
with tarfile.open(archive) as stream:
    for entry in stream.getmembers():
        if entry.name.startswith('/') or '..' in Path(entry.name).parts or not (entry.isfile() or entry.isdir()):raise ValueError('Unsafe archive entry')
    stream.extractall(destination)
cli=destination/'bower';cli.chmod(0o700)
p=subprocess.run([str(cli),'queue','verify','--database','/var/lib/bower/queue.db'],capture_output=True,text=True)
report={'phase':'ledger','host':os.environ['BOWER_LAB_HOST'],'intact':p.returncode==0,'exitCode':p.returncode}
# Export only verdict, never CLI errors that could include stored event information.
target=root/'results/ledger.json';target.write_text(json.dumps(report))
subprocess.run(['aws','s3','cp',str(target),'s3://'+os.environ['BOWER_LAB_BUCKET']+'/runs/'+os.environ['BOWER_LAB_RUN']+'/hosts/'+os.environ['BOWER_LAB_HOST']+'/ledger.json','--only-show-errors'],capture_output=True,check=True)
print(json.dumps(report))
if p.returncode:raise SystemExit(1)
PY
