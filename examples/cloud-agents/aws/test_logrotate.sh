#!/usr/bin/env bash
# Rotate the Bower event file with the shipped logrotate config, set up exactly as step 1 of
# docs/getting-started/aws-cloudwatch-agent.md says, and check the result. It adds users and
# groups and writes under /var/log, so it runs only as root in a throwaway Linux container:
#
#   docker run --rm -v "$PWD/examples/cloud-agents:/ex:ro" ubuntu:24.04 bash /ex/aws/test_logrotate.sh
#
# Needs logrotate and python3; the script installs them with apt-get or dnf when missing.
# Checked on ubuntu:24.04 and amazonlinux:2023.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# logrotate ignores a config not owned by root, and a mounted checkout is owned by the CI
# runner's user. Copy it into the container as root:root 0644, as /etc/logrotate.d would hold it.
config=/tmp/logrotate-bower-events
emit="$here/../emit_event.py"

if [[ $(id -u) -ne 0 || ! -f /.dockerenv ]]; then
  echo "run this as root inside a disposable container" >&2
  exit 2
fi
if ! command -v logrotate >/dev/null || ! command -v python3 >/dev/null || ! command -v useradd >/dev/null; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq logrotate python3-minimal >/dev/null
  else
    dnf install -y -q logrotate python3 shadow-utils util-linux procps-ng >/dev/null
  fi
fi
install -m 0644 -o root -g root "$here/logrotate-bower-events" "$config"
echo "logrotate $(logrotate --version 2>&1 | head -1 | awk '{print $2}'), fs.protected_regular=$(cat /proc/sys/fs/protected_regular)"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }
mode() { stat -c '%U:%G %a' "$1"; }
lines() { wc -l <"$1" | tr -d ' '; }

# Step 1 of the guide, word for word apart from sudo (already root).
useradd --system orders-api
groupadd --system bower-events
usermod -a -G bower-events orders-api
install -d -m 2770 -o root -g bower-events /var/log/bower
touch /var/log/bower/events.jsonl
chown root:bower-events /var/log/bower/events.jsonl
chmod 0660 /var/log/bower/events.jsonl
runuser -u orders-api -- python3 "$emit" /var/log/bower/events.jsonl >/dev/null

state=$(mktemp)
rotate() { logrotate --force --state "$state" "$1" 2>&1; }

# 1. The config as shipped before #226 (no su line) is refused: this is the regression check.
grep -v '^\s*su ' "$config" >/tmp/bower-events-nosu
out=$(rotate /tmp/bower-events-nosu || true)
grep -q 'parent directory has insecure permissions' <<<"$out" || fail "expected the no-su config to be refused: $out"
[[ ! -e /var/log/bower/events.jsonl.1 ]] || fail "no-su config rotated the file"
pass "without su, logrotate refuses the group-writable directory"

# 2. The shipped config rotates, recreates the file with the guide's owner and mode, and the
#    next event from emit_event.py (opens the file for each event) lands in the new file.
out=$(rotate "$config") || fail "logrotate failed: $out"
[[ -f /var/log/bower/events.jsonl.1 ]] || fail "events.jsonl.1 missing after rotation: $out"
[[ $(lines /var/log/bower/events.jsonl.1) -eq 1 ]] || fail "rotated file lost its event"
[[ $(mode /var/log/bower/events.jsonl) == "root:bower-events 660" ]] || fail "new file is $(mode /var/log/bower/events.jsonl)"
runuser -u orders-api -- python3 "$emit" /var/log/bower/events.jsonl >/dev/null
[[ $(lines /var/log/bower/events.jsonl) -eq 1 ]] || fail "next event did not land in the new file"
pass "rotated to events.jsonl.1; new events.jsonl is root:bower-events 0660 and receives the next event"

# 3. A writer that keeps the file open keeps appending to the renamed file until it reopens.
sync=$(mktemp -d); chmod 0777 "$sync"
# shellcheck disable=SC2016 # $1 expands in the child shell, not here.
runuser -u orders-api -- bash -c '
  exec 3>>/var/log/bower/events.jsonl
  touch "$1/open"
  while [[ ! -e "$1/rotated" ]]; do sleep 0.1; done
  echo "{\"schemaVersion\":\"held-open\"}" >&3' _ "$sync" &
writer=$!
while [[ ! -e "$sync/open" ]]; do sleep 0.1; done
rotate "$config" >/dev/null
touch "$sync/rotated"
wait "$writer"
grep -q held-open /var/log/bower/events.jsonl.1 || fail "held-open writer did not follow the renamed file"
! grep -q held-open /var/log/bower/events.jsonl || fail "held-open writer wrote to the new file"
pass "a writer holding the file open keeps writing to events.jsonl.1 until it reopens"

# 4. Two applications sharing one group in a 2770 directory can delete each other's files.
useradd --system billing-api
usermod -a -G bower-events billing-api
install -m 0660 -o root -g bower-events /dev/null /var/log/bower/billing.jsonl
runuser -u orders-api -- rm -f /var/log/bower/billing.jsonl || true
[[ ! -e /var/log/bower/billing.jsonl ]] || fail "expected 2770 to allow deleting another application's file"
pass "2770 shared by two applications: one can delete the other's file (the #247 item 14 risk)"

# 5. Sticky bit (3770): no deleting or replacing, but group members can still write each
#    other's files, and logrotate still rotates.
rm -rf /var/log/bower/*
chmod 3770 /var/log/bower
install -m 0660 -o root -g bower-events /dev/null /var/log/bower/events.jsonl
install -m 0660 -o root -g bower-events /dev/null /var/log/bower/billing.jsonl
runuser -u orders-api -- python3 "$emit" /var/log/bower/events.jsonl >/dev/null
! runuser -u billing-api -- rm -f /var/log/bower/events.jsonl 2>/dev/null || fail "3770 allowed deleting another application's file"
! runuser -u billing-api -- mv /var/log/bower/billing.jsonl /var/log/bower/events.jsonl 2>/dev/null || fail "3770 allowed replacing another application's file"
runuser -u billing-api -- bash -c 'echo injected >>/var/log/bower/events.jsonl' || fail "expected a shared group to allow appending"
out=$(rotate "$config") || fail "logrotate failed with 3770: $out"
[[ -f /var/log/bower/events.jsonl.1 && $(mode /var/log/bower/events.jsonl) == "root:bower-events 660" ]] || fail "3770 rotation: $out"
runuser -u orders-api -- python3 "$emit" /var/log/bower/events.jsonl >/dev/null
pass "3770: delete and replace refused, rotation works, but billing-api could still append to orders-api's file"

# 6. One group per application, one directory each: the other application can't read,
#    write, delete or create anything, and logrotate rotates with a matching su line.
rm -rf /var/log/bower
install -d -m 0755 -o root -g root /var/log/bower
for app in orders-api billing-api; do
  groupadd --system "bower-$app"
  usermod -a -G "bower-$app" "$app"
  install -d -m 2770 -o root -g "bower-$app" "/var/log/bower/$app"
  install -m 0660 -o root -g "bower-$app" /dev/null "/var/log/bower/$app/events.jsonl"
  sed -e "s|/var/log/bower/events.jsonl|/var/log/bower/$app/events.jsonl|" \
      -e "s|bower-events|bower-$app|g" "$config" >"/tmp/bower-$app.logrotate"
done
runuser -u orders-api -- python3 "$emit" /var/log/bower/orders-api/events.jsonl >/dev/null
! runuser -u billing-api -- cat /var/log/bower/orders-api/events.jsonl >/dev/null 2>&1 || fail "billing-api read orders-api's file"
! runuser -u billing-api -- bash -c 'echo injected >>/var/log/bower/orders-api/events.jsonl' 2>/dev/null || fail "billing-api wrote orders-api's file"
! runuser -u billing-api -- touch /var/log/bower/orders-api/other.jsonl 2>/dev/null || fail "billing-api created a file in orders-api's directory"
out=$(rotate /tmp/bower-orders-api.logrotate) || fail "per-application rotation: $out"
[[ -f /var/log/bower/orders-api/events.jsonl.1 && $(mode /var/log/bower/orders-api/events.jsonl) == "root:bower-orders-api 660" ]] || fail "per-application rotation: $out"
pass "one group per application: no cross-application read, write or create, and rotation works"

echo "all logrotate checks passed"
