#!/bin/bash
set -euo pipefail
umask 077
B='{{Artifacts}}'; R='{{REGION}}'
dnf install -y nftables >>/var/log/bower-lab-packages.log 2>&1
mkdir -p /opt/bower-lab/restore && cd /opt/bower-lab
for f in pr.rpm nftables-validation-1.0.0.bowerpack bower-signing.pub.pem; do aws s3 cp "s3://$B/artifacts/$f" "$f" --region "$R" --only-show-errors; done
aws s3 cp "s3://$B/backups/{{NAME}}.bowerbackup" restore/ --region "$R" --only-show-errors
aws s3 cp "s3://$B/backups/{{NAME}}.bowerbackup.manifest.json" restore/ --region "$R" --only-show-errors
dnf install -y /opt/bower-lab/pr.rpm >>/var/log/bower-lab-packages.log 2>&1
systemctl stop bower
# The package's first start created an empty queue; restore never overwrites, so move it aside.
install -d -m 0700 /opt/bower-lab/fresh-queue && mv /var/lib/bower/queue.db* /opt/bower-lab/fresh-queue/ 2>/dev/null || true
start=$(date -u +%s.%N)
/usr/bin/bower queue restore --backup /opt/bower-lab/restore/{{NAME}}.bowerbackup --database /var/lib/bower/queue.db > /opt/bower-lab/restore/restore.out 2>/opt/bower-lab/restore/restore.err
end=$(date -u +%s.%N)
chown bower:bower /var/lib/bower/queue.db
install -d -o root -g bower -m 0750 /etc/bower/tls
install -m 0644 nftables-validation-1.0.0.bowerpack /etc/bower/packs/firewall.bowerpack
install -m 0644 bower-signing.pub.pem /etc/bower/keys/bower-signing.pub.pem
for f in ca.pem server.pem server.key; do aws s3 cp "s3://$B/credentials/$f" "/etc/bower/tls/$f" --region "$R" --only-show-errors; done
aws s3 cp "s3://$B/credentials/ingest.pem" /etc/bower/secrets/ingest.pem --region "$R" --only-show-errors
aws s3 cp "s3://$B/credentials/hmac-linux" /etc/bower/secrets/hmac.key --region "$R" --only-show-errors
aws s3 cp "s3://$B/credentials/token-linux" /etc/bower/secrets/token --region "$R" --only-show-errors
install -d -m 0755 /etc/bower/no-defaults
cat >/etc/bower/syslog.json <<'JSON'
{"apiVersion":"bower.security/v1","kind":"SyslogSource","listeners":[{"id":"firewall","protocol":"tls","address":"0.0.0.0","port":6514,"idleTimeoutSeconds":3600,"allowedSenders":["{{Linux2Ip}}/32","127.0.0.1/32"],"routes":[{"pack":"nftables-validation","parser":0,"appName":"nftables"}],"tls":{"certificateFile":"/etc/bower/tls/server.pem","privateKeyFile":"/etc/bower/tls/server.key","clientCertificateAuthorityFile":"/etc/bower/tls/ca.pem"}}]}
JSON
cat >/etc/bower/bower.env <<'ENV'
BOWER_LISTEN_URL=http://127.0.0.1:4319
BOWER_INGEST_TOKEN_FILE=/etc/bower/secrets/token
BOWER_QUEUE_PATH=/var/lib/bower/queue.db
BOWER_POLICY_DIRECTORY=/etc/bower/no-defaults
BOWER_COLLECTOR_ID=linux-ws4
BOWER_ENVIRONMENT=validation
BOWER_OUTPUT=azure-logs-ingestion
BOWER_AZURE_CREDENTIAL=environment
BOWER_DCE_ENDPOINT={{DCE}}
BOWER_DCR_ID={{DCR}}
AZURE_TENANT_ID={{AZURE_TENANT}}
AZURE_CLIENT_ID={{AZURE_CLIENT}}
AZURE_CLIENT_CERTIFICATE_PATH=/etc/bower/secrets/ingest.pem
BOWER_PACKS=/etc/bower/packs/firewall.bowerpack
BOWER_PACK_TRUSTED_KEYS=/etc/bower/keys/bower-signing.pub.pem
BOWER_SYSLOG_CONFIG=/etc/bower/syslog.json
BOWER_PRIVACY_HMAC_KEY_FILE=/etc/bower/secrets/hmac.key
BOWER_DELIVERY_LEASE_SECONDS=90
BOWER_DELIVERY_TIMEOUT_SECONDS=60
ENV
chown root:bower /etc/bower/secrets/* /etc/bower/tls/* /etc/bower/syslog.json /etc/bower/bower.env
chmod 0640 /etc/bower/secrets/* /etc/bower/tls/* /etc/bower/syslog.json /etc/bower/bower.env
systemctl start bower
sleep 6
python3 -c "
import json,os,stat;m=json.load(open('/opt/bower-lab/restore/restore.out'))
s=os.stat('/var/lib/bower/queue.db')
print(json.dumps({'restoreSeconds':round($end-$start,2),'counts':m['Counts'],'ledger':m['LedgerSequence'],'integrity':m['IntegrityCheck'],'owner':'%d:%d'%(s.st_uid,s.st_gid),'mode':oct(stat.S_IMODE(s.st_mode)),'stderr':open('/opt/bower-lab/restore/restore.err').read().strip()[:200]}))"
systemctl is-active bower
