#!/bin/bash
set -euo pipefail
umask 077
install -d -m 0700 /var/lib/bower-lab/backup
out=/var/lib/bower-lab/backup/{{NAME}}.bowerbackup
start=$(date -u +%s.%N)
/usr/bin/bower queue backup --database {{QUEUE}} --output "$out" --collector-id {{COLLECTOR_ID}} > /var/lib/bower-lab/backup/{{NAME}}.out
end=$(date -u +%s.%N)
aws s3 cp "$out" "s3://{{Artifacts}}/backups/{{NAME}}.bowerbackup" --region "{{REGION}}" --only-show-errors
aws s3 cp "$out.manifest.json" "s3://{{Artifacts}}/backups/{{NAME}}.bowerbackup.manifest.json" --region "{{REGION}}" --only-show-errors
aws s3 cp "$out.manifest.json" "s3://{{Artifacts}}/results/$(hostname -s)/{{NAME}}.manifest.json" --region "{{REGION}}" --only-show-errors
python3 -c "
import json,hashlib;m=json.load(open('$out.manifest.json'))
print(json.dumps({'name':'{{NAME}}','seconds':round($end-$start,2),'bytes':m['databaseBytes'],'counts':m['counts'],'cursors':m['sourceCursors'],'ledger':m['ledgerSequence'],'intact':m['ledgerIntact'],'integrity':m['integrityCheck'],'cli':hashlib.sha256(open('/opt/bower/bower','rb').read()).hexdigest(),'permissions':oct(__import__('os').stat('$out').st_mode&0o777)}))"
