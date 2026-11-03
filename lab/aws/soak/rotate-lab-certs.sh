#!/bin/bash
# Replace the lab syslog CA and this host's certificate with longer-lived copies issued for the
# same private keys (public certificates only cross S3), verify them, and restart the service
# that uses them. Before generation only. ROLE=collector|sender; SHA256 values are public.
set -euo pipefail
umask 077
: "${BOWER_LAB_BUCKET:?}" "${BOWER_LAB_RUN:?}" "${ROLE:?}" "${CA_SHA256:?}" "${CERT_SHA256:?}"
[[ "$BOWER_LAB_RUN" =~ ^bower-(re)?soak-[0-9]{8}-[0-9]{6}$ ]]
stage=$(mktemp -d); trap 'rm -rf -- "$stage"' EXIT
if [ "$ROLE" = collector ]; then
  src="artifacts/soak/linux"; cert=server; dir=/etc/bower/syslog; key=$dir/server-key.pem; target=$dir/server.pem; unit=bower
else
  src="artifacts/qualification/$BOWER_LAB_RUN/sender"; cert=sender-r; dir=/etc/pki/bower-lab; key=$dir/sender-r-key.pem; target=$dir/sender-r.pem; unit=rsyslog
fi
aws s3 cp --only-show-errors "s3://$BOWER_LAB_BUCKET/$src/rotate-ca.pem" "$stage/ca.pem"
aws s3 cp --only-show-errors "s3://$BOWER_LAB_BUCKET/$src/rotate-$cert.pem" "$stage/cert.pem"
echo "$CA_SHA256  $stage/ca.pem" | sha256sum --check --strict --quiet
echo "$CERT_SHA256  $stage/cert.pem" | sha256sum --check --strict --quiet
openssl verify -CAfile "$stage/ca.pem" "$stage/cert.pem" >/dev/null
[ "$(openssl x509 -in "$stage/cert.pem" -pubkey -noout)" = "$(openssl pkey -in "$key" -pubout)" ]
for pair in "ca.pem:$dir/ca.pem" "cert.pem:$target"; do
  from=${pair%%:*}; to=${pair#*:}
  install -m "$(stat -c %a "$to")" -o "$(stat -c %U "$to")" -g "$(stat -c %G "$to")" "$stage/$from" "$to"
done
systemctl restart "$unit"
sleep 3
echo "{\"role\":\"$ROLE\",\"active\":\"$(systemctl is-active "$unit")\",\"notAfter\":\"$(openssl x509 -in "$target" -noout -enddate | cut -d= -f2)\"}"
