#!/bin/bash
# Storage-pressure lab, Linux collector. Run as root through storage-lab.py only.
# Formats the dedicated 1 GiB queue volume, installs the CI RPM and a local rsyslog
# sender (disk-assisted queue, mutual TLS) and configures Azure Logs Ingestion.
# Prints metadata only: never key material, tokens or event payloads.
set -euo pipefail
umask 077
: "${BOWER_LAB_RUN:?}" "${BOWER_LAB_BUCKET:?}" "${BOWER_DCE:?}" "${BOWER_DCR:?}" "${BOWER_TENANT:?}" "${BOWER_PUBLISHER:?}"
[[ "$BOWER_LAB_RUN" =~ ^bower-ws3-[0-9]{8}-[0-9]{6}$ ]]
[ "$(id -u)" = 0 ]
artifacts=/root/ws3-artifacts
mkdir -p "$artifacts"
aws s3 cp --quiet --recursive "s3://$BOWER_LAB_BUCKET/$BOWER_LAB_RUN/artifacts/linux/" "$artifacts/"
(cd "$artifacts" && sha256sum -c --quiet SHA256SUMS)

# The queue volume: the only non-root disk of exactly 1 GiB.
root_disk=$(lsblk -no PKNAME "$(findmnt -no SOURCE /)")
data_disk=$(lsblk -dbno NAME,SIZE,TYPE | awk -v root="$root_disk" '$3=="disk" && $1!=root && $2==1073741824 {print $1}')
[ "$(echo "$data_disk" | wc -w)" = 1 ]
if ! findmnt -n /var/lib/bower >/dev/null; then
  mkfs.xfs -q -L bowerqueue "/dev/$data_disk"
  mkdir -p /var/lib/bower
  echo "LABEL=bowerqueue /var/lib/bower xfs defaults,nofail,noatime 0 2" >> /etc/fstab
  mount /var/lib/bower
fi

dnf install -q -y rsyslog rsyslog-gnutls nftables sqlite jq python3 >/dev/null
dnf install -q -y "$artifacts/collector.rpm" >/dev/null
chown bower:bower /var/lib/bower && chmod 0700 /var/lib/bower

install -d -m 0750 -o root -g bower /etc/bower/secrets /etc/bower/syslog /etc/bower/packs /etc/bower/keys
install -m 0640 -o root -g bower "$artifacts/storage-pressure-validation-1.0.0.bowerpack" /etc/bower/packs/
install -m 0640 -o root -g bower "$artifacts/lab.pub.pem" /etc/bower/keys/pack-trusted.pem
aws secretsmanager get-secret-value --secret-id "bower-lab/$BOWER_LAB_RUN/publisher" \
  --query SecretString --output text > /etc/bower/secrets/azure-publisher.pem
chown root:bower /etc/bower/secrets/azure-publisher.pem && chmod 0640 /etc/bower/secrets/azure-publisher.pem
[ -s /etc/bower/secrets/hmac.key ] || head -c 32 /dev/urandom | base64 > /etc/bower/secrets/hmac.key
[ -s /etc/bower/secrets/ingest-token ] || head -c 48 /dev/urandom | base64 | tr -d '+/=' > /etc/bower/secrets/ingest-token
chown root:bower /etc/bower/secrets/hmac.key /etc/bower/secrets/ingest-token
chmod 0640 /etc/bower/secrets/hmac.key /etc/bower/secrets/ingest-token

# Ephemeral host-only CA: the syslog server certificate and the rsyslog client certificate.
tls=/etc/bower/syslog
if [ ! -s "$tls/ca.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=ws3 lab CA" \
    -keyout "$tls/ca-key.pem" -out "$tls/ca.pem" 2>/dev/null
  for name in server client; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=bower-$name" \
      -keyout "$tls/$name-key.pem" -out "$tls/$name.csr" 2>/dev/null
    printf 'subjectAltName=DNS:localhost,DNS:bower-%s,IP:127.0.0.1\nextendedKeyUsage=%s\n' "$name" \
      "$([ $name = server ] && echo serverAuth || echo clientAuth)" > "$tls/$name.ext"
    openssl x509 -req -in "$tls/$name.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca-key.pem" -CAcreateserial \
      -days 2 -extfile "$tls/$name.ext" -out "$tls/$name.pem" 2>/dev/null
  done
  rm -f "$tls"/*.csr "$tls"/*.ext "$tls/ca-key.pem" "$tls"/*.srl
  install -d -m 0700 /etc/rsyslog.d/tls
  mv "$tls/client.pem" "$tls/client-key.pem" /etc/rsyslog.d/tls/
  cp "$tls/ca.pem" /etc/rsyslog.d/tls/ca.pem
  chown root:bower "$tls"/* && chmod 0640 "$tls"/*
fi

cat > /etc/bower/syslog.json <<'JSON'
{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [
  {"id": "sender-tls", "protocol": "tls", "address": "127.0.0.1", "port": 6514, "allowedSenders": ["127.0.0.1"],
   "idleTimeoutSeconds": 3600,
   "tls": {"certificateFile": "/etc/bower/syslog/server.pem", "privateKeyFile": "/etc/bower/syslog/server-key.pem",
           "clientCertificateAuthorityFile": "/etc/bower/syslog/ca.pem"},
   "routes": [{"appName": "bowerseq", "pack": "storage-pressure-validation", "parser": 0}]}]}
JSON
chown root:bower /etc/bower/syslog.json && chmod 0640 /etc/bower/syslog.json

cat > /etc/bower/bower.env <<ENV
BOWER_COLLECTOR_ID=ws3-linux
BOWER_ENVIRONMENT=validation
BOWER_PACKS=/etc/bower/packs/storage-pressure-validation-1.0.0.bowerpack
BOWER_PACK_TRUSTED_KEYS=/etc/bower/keys/pack-trusted.pem
BOWER_PRIVACY_HMAC_KEY_FILE=/etc/bower/secrets/hmac.key
BOWER_INGEST_TOKEN_FILE=/etc/bower/secrets/ingest-token
BOWER_SYSLOG_CONFIG=/etc/bower/syslog.json
BOWER_OUTPUT=azure-logs-ingestion
BOWER_DCE_ENDPOINT=$BOWER_DCE
BOWER_DCR_ID=$BOWER_DCR
BOWER_AZURE_CREDENTIAL=environment
AZURE_TENANT_ID=$BOWER_TENANT
AZURE_CLIENT_ID=$BOWER_PUBLISHER
AZURE_CLIENT_CERTIFICATE_PATH=/etc/bower/secrets/azure-publisher.pem
BOWER_DELIVERY_LEASE_SECONDS=90
BOWER_DELIVERY_TIMEOUT_SECONDS=60
BOWER_QUEUE_MAX_BYTES=${BOWER_QUEUE_MAX_BYTES:-67108864}
BOWER_STORAGE_WARNING_FREE_BYTES=${BOWER_WARNING_BYTES:-268435456}
BOWER_STORAGE_WARNING_FREE_PERCENT=0
BOWER_STORAGE_CRITICAL_FREE_BYTES=${BOWER_CRITICAL_BYTES:-134217728}
BOWER_STORAGE_CRITICAL_FREE_PERCENT=0
BOWER_QUEUE_PRESSURE_RETENTION_MINUTES=${BOWER_PRESSURE_MINUTES:-5}
ENV
chown root:bower /etc/bower/bower.env && chmod 0640 /etc/bower/bower.env

# Sender: generator -> rsyslog (plain loopback TCP) -> disk-assisted action queue on the
# root volume -> persistent mutually authenticated RFC 5424 to Bower.
mkdir -p /var/spool/rsyslog /var/log/ws3
cat > /etc/rsyslog.d/50-ws3.conf <<'CONF'
module(load="impstats" interval="5" format="json" log.file="/var/log/ws3/rsyslog-stats.json" resetCounters="off")
module(load="imtcp" StreamDriver.Name="ptcp")
input(type="imtcp" address="127.0.0.1" port="5514" ruleset="ws3")
global(DefaultNetstreamDriverCAFile="/etc/rsyslog.d/tls/ca.pem"
       DefaultNetstreamDriverCertFile="/etc/rsyslog.d/tls/client.pem"
       DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/tls/client-key.pem")
ruleset(name="ws3" queue.type="LinkedList" queue.size="200000") {
  action(type="omfwd" name="bower" target="127.0.0.1" port="6514" protocol="tcp"
         TCP_Framing="octet-counted" template="RSYSLOG_SyslogProtocol23Format"
         StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
         StreamDriverPermittedPeers="bower-server" RebindInterval="0"
         queue.type="LinkedList" queue.filename="ws3-bower" queue.size="100000"
         queue.maxDiskSpace="2g" queue.saveOnShutdown="on" queue.highWatermark="60000"
         action.resumeRetryCount="-1" action.resumeInterval="2")
}
CONF
rsyslogd -N1 >/dev/null 2>&1
systemctl enable -q --now rsyslog && systemctl restart rsyslog
systemctl enable -q bower && systemctl restart bower
for _ in $(seq 1 60); do
  curl -fsS http://127.0.0.1:4319/health >/dev/null 2>&1 && break
  sleep 2
done
token=$(cat /etc/bower/secrets/ingest-token)
status=$(curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:4319/v1/status)
jq -n --argjson s "$status" --arg rpm "$(sha256sum "$artifacts/collector.rpm" | cut -d' ' -f1)" \
  --arg version "$(rpm -q --qf "%{VERSION}-%{RELEASE}" bower-collector 2>/dev/null || true)" \
  --arg fs "$(findmnt -no FSTYPE,SIZE,AVAIL /var/lib/bower)" \
  '{phase:"linux-setup", rpmSha256:$rpm, package:$version, queueMount:$fs, health:$s.status,
    storage:$s.storage, syslog:[$s.syslog[] | {id, protocol, endpoint}], packs:[$s.policy.packs[] | {id, version, packHash}]}'
