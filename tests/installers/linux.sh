#!/usr/bin/env bash
# CI install tests for the Linux packages (#112). Needs the amd64 packages and offline
# bundle in <packages-dir>, a development-mode management API on 127.0.0.1:4320, sudo,
# docker, jq, openssl and uvx on the runner.
#
# 1. Ubuntu, offline bundle (deb): silent install with a pre-seeded token and trusted pack
#    key joins Pending; remove leaves no secret; purge leaves nothing.
# 2. Ubuntu, Ansible role (deb): the same through deploy/ansible.
# 3. Rocky Linux 9 container with systemd, offline bundle (rpm): the same with dnf remove.
#
# Tokens are written only to files under a private work directory; none is printed.
set -euo pipefail

packages="$(cd "${1:?packages directory}" && pwd)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
base=http://127.0.0.1:4320
rocky_image="rockylinux/rockylinux:9-ubi-init@sha256:4a0c9370f20d3598bacf9d43393f85fd356ef1caa9bf93f7745a5cf5f23edab3"
work="$(mktemp -d)"
chmod 700 "$work"
secrets="$work/secrets"
touch "$secrets"

cleanup() {
  status=$?
  docker rm -f bower-rocky >/dev/null 2>&1 || true
  if [ "$status" -ne 0 ]; then
    # Never print a token, even on failure.
    sudo journalctl -u bower.service --no-pager -n 100 2>/dev/null | grep -v -F -f "$secrets" || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

new_token() {
  local token
  token="$(curl -sf -X POST -H 'Content-Type: application/json' \
    -d "{\"environment\":\"ci\",\"collectorId\":\"$1\",\"reason\":\"CI installer test\",\"expiresInHours\":1}" \
    "$base/api/enrolment-tokens" | jq -r .token)"
  printf '%s\n' "$token" >>"$secrets"
  printf '%s\n' "$token" >"$2"
}

status_of() {
  curl -s "$base/api/collectors/$1" | jq -r '.status // "missing"' 2>/dev/null || echo missing
}

wait_for_pending() {
  for _ in $(seq 1 60); do
    if [ "$(status_of "$1")" = Pending ]; then
      echo "$1 joined Pending"
      return 0
    fi
    sleep 2
  done
  echo "$1 never joined Pending (last: $(status_of "$1"))" >&2
  return 1
}

prepare_bundle() {
  local id="$1" target="$2"
  tar -xzf "$packages"/bower-collector-offline-*-linux-amd64.tar.gz -C "$target"
  local bundle
  bundle="$(find "$target" -maxdepth 1 -type d -name 'bower-collector-offline-*')"
  new_token "$id" "$bundle/seed/enrolment-token"
  openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl ec -pubout 2>/dev/null \
    >"$bundle/seed/pack-trusted.pem"
  printf 'BOWER_MANAGEMENT_ENDPOINT=%s/\nBOWER_COLLECTOR_ID=%s\nBOWER_ENVIRONMENT=ci\n' "$base" "$id" \
    >"$bundle/seed/settings.env"
  echo "$bundle"
}

echo "== Ubuntu: offline bundle (deb)"
mkdir "$work/deb"
bundle="$(prepare_bundle ubuntu-offline "$work/deb")"
sudo "$bundle/install.sh" --wait 120
[ ! -e "$bundle/seed/enrolment-token" ] || { echo "seed token left in the bundle" >&2; exit 1; }
wait_for_pending ubuntu-offline
# An operator secret file; uninstall must remove it too.
sudo install -o root -g bower -m 0640 /dev/null /etc/bower/secrets/ingest-token
sudo bash "$here/assert-linux.sh" installed "$secrets"
sudo apt-get remove -y bower-collector >/dev/null
sudo bash "$here/assert-linux.sh" removed
sudo apt-get purge -y bower-collector >/dev/null
sudo bash "$here/assert-linux.sh" purged

echo "== Ubuntu: Ansible role (deb)"
new_token ubuntu-ansible "$work/ansible-token"
jq -n --rawfile token "$work/ansible-token" --arg package "$(ls "$packages"/bower-collector_*_amd64.deb)" \
  --arg endpoint "$base/" \
  '{bower_package: $package, bower_management_endpoint: $endpoint, bower_collector_id: "ubuntu-ansible",
    bower_environment: "ci", bower_enrolment_token: ($token | rtrimstr("\n")),
    ansible_python_interpreter: "/usr/bin/python3"}' >"$work/vars.json"
ansible=(env ANSIBLE_ROLES_PATH="$repo/deploy/ansible/roles" ANSIBLE_NOCOLOR=1
  uvx --from ansible-core==2.21.5 ansible-playbook -i "localhost," -c local)
"${ansible[@]}" -e "@$work/vars.json" "$here/ansible-playbook.yml"
wait_for_pending ubuntu-ansible
sudo bash "$here/assert-linux.sh" installed "$secrets"
# A second run is idempotent: the consumed token is not written again.
"${ansible[@]}" -e "@$work/vars.json" "$here/ansible-playbook.yml"
sudo test ! -e /var/lib/bower/enrolment/enrolment-token
"${ansible[@]}" -e "@$work/vars.json" -e bower_state=absent "$here/ansible-playbook.yml"
sudo bash "$here/assert-linux.sh" removed
"${ansible[@]}" -e "@$work/vars.json" -e bower_state=absent -e bower_purge=true "$here/ansible-playbook.yml"
sudo apt-get purge -y bower-collector >/dev/null 2>&1 || true

echo "== Rocky Linux 9 (systemd container): offline bundle (rpm)"
mkdir "$work/rpm"
bundle="$(prepare_bundle rocky-offline "$work/rpm")"
docker run -d --name bower-rocky --privileged --cgroupns=host --network host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw "$rocky_image" /usr/sbin/init >/dev/null
for _ in $(seq 1 30); do
  docker exec bower-rocky systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
  sleep 1
done
docker cp "$bundle" bower-rocky:/root/bundle
docker cp "$here/assert-linux.sh" bower-rocky:/root/assert-linux.sh
docker cp "$secrets" bower-rocky:/root/secrets
docker exec bower-rocky /root/bundle/install.sh --wait 120
docker exec bower-rocky test ! -e /root/bundle/seed/enrolment-token
wait_for_pending rocky-offline
docker exec bower-rocky install -o root -g bower -m 0640 /dev/null /etc/bower/secrets/ingest-token
docker exec bower-rocky bash /root/assert-linux.sh installed /root/secrets
docker exec bower-rocky dnf remove -y bower-collector >/dev/null
docker exec bower-rocky bash /root/assert-linux.sh removed

echo "Linux installer tests passed: Ubuntu deb (offline bundle and Ansible) and Rocky Linux 9 rpm."
