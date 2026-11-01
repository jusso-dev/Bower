#!/bin/bash
# Docker collector with the same CI binaries on the official chiseled runtime-deps base image.
set -euo pipefail
umask 077
B='{{Artifacts}}'; R='{{REGION}}'
systemctl is-enabled bower >/dev/null 2>&1 && { echo 'rpm service still enabled'; exit 1; } || true
systemctl enable --now docker >/dev/null
aws s3 cp "s3://$B/artifacts/pr-linux-x64.tar.gz" /opt/bower-lab/pr-linux-x64.tar.gz --region "$R" --only-show-errors
for tag in 264 277; do
  d=/opt/bower-docker/build-$tag; rm -rf "$d"; mkdir -p "$d/state" "$d/no-defaults"
  if [ $tag = 264 ]; then tar -C "$d" -xzf /opt/bower-lab/old-linux-x64.tar.gz; else tar -C "$d" -xzf /opt/bower-lab/pr-linux-x64.tar.gz collector; fi
  rm -f "$d"/collector/*.dbg
  cat >"$d/Dockerfile" <<'DOCKER'
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0.14-noble-chiseled
WORKDIR /app
COPY collector/ /app/
COPY --chown=1654:1654 state/ /var/lib/bower/
COPY no-defaults/ /app/no-defaults/
USER 1654:1654
ENV ASPNETCORE_HTTP_PORTS= BOWER_LISTEN_URL=http://127.0.0.1:4319 BOWER_QUEUE_PATH=/var/lib/bower/queue.db BOWER_POLICY_DIRECTORY=/app/no-defaults DOTNET_gcServer=0
VOLUME ["/var/lib/bower"]
ENTRYPOINT ["/app/Bower.Collector"]
DOCKER
  chmod -R a+rX "$d"
  docker build -q -t bower-lab:$tag "$d" >/dev/null
done
e=/opt/bower-docker/etc; mkdir -p $e/secrets $e/tls $e/packs $e/keys
cp /etc/bower/tls/ca.pem /etc/bower/tls/server.pem /etc/bower/tls/server.key $e/tls/
cp /etc/bower/packs/firewall.bowerpack $e/packs/; cp /etc/bower/keys/bower-signing.pub.pem $e/keys/
cp /etc/bower/secrets/ingest.pem /etc/bower/secrets/hmac.key $e/secrets/
aws s3 cp "s3://$B/credentials/token-docker" $e/secrets/token --region "$R" --only-show-errors
sed 's#"allowedSenders":\[[^]]*\]#"allowedSenders":["{{Linux2Ip}}/32"]#' /etc/bower/syslog.json > $e/syslog.json
grep -v -E '^(BOWER_COLLECTOR_ID|BOWER_QUEUE_PATH|BOWER_POLICY_DIRECTORY|BOWER_INGEST_TOKEN_FILE|BOWER_LISTEN_URL)=' /etc/bower/bower.env > /opt/bower-docker/docker.env
printf 'BOWER_COLLECTOR_ID=linux-docker-ws4\nBOWER_INGEST_TOKEN_FILE=/etc/bower/secrets/token\n' >> /opt/bower-docker/docker.env
chown -R 1654:1654 $e; chmod -R u=rX,go= $e
docker volume create bower-data >/dev/null
docker images bower-lab
echo ready
