#!/bin/bash
# Image swap: stop the running container (SIGTERM, 30 s grace), start TAG with the same volume.
set -euo pipefail
old=$(docker ps -q --filter name=^bower-c$ || true)
old_image=$( [ -n "$old" ] && docker inspect -f '{{.Config.Image}}' bower-c || echo none)
t0=$(date -u +%s.%N)
if docker ps -aq --filter name=^bower-c$ | grep -q .; then docker stop -t 30 bower-c >/dev/null; docker rm bower-c >/dev/null; fi
t1=$(date -u +%s.%N)
docker run -d --name bower-c --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  --restart unless-stopped --tmpfs /tmp:size=16m --env-file /opt/bower-docker/docker.env \
  -v bower-data:/var/lib/bower -v /opt/bower-docker/etc:/etc/bower:ro bower-lab:{{TAG}} >/dev/null
for i in $(seq 1 60); do curl -fsS -o /dev/null http://127.0.0.1:4319/health && break; sleep 0.5; done
t2=$(date -u +%s.%N)
echo "{\"label\":\"{{LABEL}}\",\"from\":\"$old_image\",\"to\":\"bower-lab:{{TAG}}\",\"stopSeconds\":$(python3 -c "print(round($t1-$t0,2))"),\"healthySeconds\":$(python3 -c "print(round($t2-$t1,2))"),\"user\":\"$(docker inspect -f '{{.Config.User}}' bower-c)\",\"volume\":\"$(docker inspect -f '{{range .Mounts}}{{.Name}}{{end}}' bower-c)\",\"state\":\"$(docker inspect -f '{{.State.Status}}' bower-c)\"}"
