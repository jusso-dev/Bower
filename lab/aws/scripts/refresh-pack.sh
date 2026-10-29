#!/bin/bash
set -euo pipefail
umask 077
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/manifest.json" /opt/bower-lab/manifest.json --only-show-errors
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/lab-pack.tar.gz" /opt/bower-lab/lab-pack.tar.gz --only-show-errors
python3 - <<'PY'
import sys, json, hashlib, base64, tarfile, tempfile
from pathlib import Path
sys.path.insert(0,'/opt/bower-lab')
import control
root=control.ROOT
manifest=json.loads((root/'manifest.json').read_text())
if manifest['runId']!=control.RUN or control.aws('sts','get-caller-identity')['Account']!=manifest['account']:
    raise SystemExit('Lab identity mismatch')
archive=root/'lab-pack.tar.gz'
if hashlib.sha256(archive.read_bytes()).hexdigest()!=manifest['files']['lab-pack.tar.gz']:
    raise SystemExit('Pack source checksum mismatch')
with tempfile.TemporaryDirectory(prefix='pack-refresh-',dir=root) as directory:
    temporary=Path(directory)
    with tarfile.open(archive) as stream:
        for entry in stream.getmembers():
            if entry.name.startswith('/') or '..' in Path(entry.name).parts or not (entry.isfile() or entry.isdir()):
                raise SystemExit('Unsafe pack archive entry')
        stream.extractall(temporary/'source')
    cli=str(root/'cli/bower')
    control.run(cli,'pack','build',str(temporary/'source'),'--key',str(root/'pack-key/lab.key.pem'),'--out',str(temporary/'output'))
    built=list((temporary/'output').glob('*.bowerpack'))
    if len(built)!=1:
        raise SystemExit('Expected exactly one newly built pack')
    pack=built[0]
    control.run(cli,'pack','test',str(pack),'--trusted-key',str(root/'pack-key/lab.pub.pem'))
    for host in manifest['hosts']:
        if host=='Control': continue
        bundle=json.loads(control.aws('secretsmanager','get-secret-value','--secret-id','bower-lab/'+control.RUN+'/'+host)['SecretString'])
        bundle['pack']=base64.b64encode(pack.read_bytes()).decode()
        control.store_secret(host,bundle)
    pack_hash=hashlib.sha256(pack.read_bytes()).hexdigest()
control.write(root/'setup-complete',control.RUN+'\n')
print(json.dumps({'phase':'pack-refresh','status':'passed','sha256':pack_hash}))
PY
