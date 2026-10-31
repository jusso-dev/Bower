#!/bin/bash
set -euo pipefail
umask 077
B='{{Artifacts}}'; R='{{REGION}}'
dnf install -y python3 sqlite >/var/log/bower-lab-packages.log 2>&1
mkdir -p /opt/bower-lab /etc/bower-sender
aws s3 cp "s3://$B/artifacts/sender.py" /opt/bower-lab/sender.py --region "$R" --only-show-errors
for f in ca.pem client.pem client.key; do aws s3 cp "s3://$B/credentials/$f" "/etc/bower-sender/$f" --region "$R" --only-show-errors; done
chmod 0600 /etc/bower-sender/*
python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)'
echo 'sender ready'
