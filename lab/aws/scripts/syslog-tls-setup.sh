#!/bin/bash
# Prepare one owned Amazon Linux 2023 lab host for syslog-tls-rotation.py.
# Usage (root, through SSM): syslog-tls-setup.sh ARTIFACT_URL ARTIFACT_SHA256 RUN_ID
# The artifact holds only public material: the collector build, a signed pack, its
# public trust key and the lab scripts. All private keys are generated on the host.
set -euo pipefail
url="$1"; expected="$2"; run_id="$3"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
case "$run_id" in bower-*) ;; *) echo "unexpected run id" >&2; exit 1 ;; esac

dnf install -y -q rsyslog rsyslog-openssl openssl python3 >/dev/null
id bower >/dev/null 2>&1 || useradd --system --home-dir /var/lib/bower-ws5 --shell /sbin/nologin bower

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
curl --fail --silent --show-error --proto '=https' --tlsv1.2 -o "$work/artifact.tar.gz" "$url"
actual=$(sha256sum "$work/artifact.tar.gz" | cut -d' ' -f1)
[ "$actual" = "$expected" ] || { echo "artifact hash mismatch" >&2; exit 1; }

install -d -m 0755 /opt/bower /etc/bower-ws5 /etc/bower-ws5/packs /etc/bower-ws5/keys /opt/bower-ws5
tar -xzf "$work/artifact.tar.gz" -C "$work"
rm -rf /opt/bower/collector && cp -a "$work/collector" /opt/bower/collector
chown -R root:root /opt/bower/collector && chmod -R u=rwX,go=rX /opt/bower/collector
install -m 0644 "$work"/packs/*.bowerpack /etc/bower-ws5/packs/
install -m 0644 "$work/keys/pack-trusted.pem" /etc/bower-ws5/keys/pack-trusted.pem
install -m 0700 "$work"/scripts/*.py /opt/bower-ws5/

echo "{\"setup\":\"installed\",\"artifactSha256\":\"$actual\",\"collectorSha256\":\"$(sha256sum /opt/bower/collector/Bower.Collector.dll | cut -d' ' -f1)\",\"rsyslog\":\"$(rpm -q rsyslog)\",\"tlsDriver\":\"$(rpm -q rsyslog-openssl)\",\"kernel\":\"$(uname -r)\"}"
python3 /opt/bower-ws5/syslog-tls-rotation.py --run-id "$run_id" --phase setup
