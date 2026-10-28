#!/usr/bin/env bash
# Relay mode end to end in compose (#110). Needs the CI images bower-management:ci,
# bower-collector:ci and bower-collector-rs:ci, plus jq and openssl on the host.
#
# Three tiers: management (loopback only), two relays (C# and Rust) that share its network
# namespace, and two downstream collectors with no route to management. Each downstream
# enrols, heartbeats and delivers through the other runtime's relay. The test proves:
# enrolment and Active status through the tunnel, delivery of every event exactly once to
# the relay's destination (AMA spool), events held at the edge while a relay is down and
# delivered once after it restarts, and no token or key material in any log.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
export BOWER_E2E_DIR="$work"
compose=(docker compose -p bower-relay-e2e -f "$here/../../deploy/docker/compose.relay-e2e.yaml" --profile relays --profile edges)
base=http://127.0.0.1:4320
touch "$work/secrets"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    # Never print a token, even on failure.
    "${compose[@]}" logs --no-color 2>&1 | grep -v -F -f "$work/secrets" || true
  fi
  "${compose[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

api() {
  docker run --rm --network container:bower-relay-e2e-management curlimages/curl:8.11.1 -sS "$@"
}

post() {
  api -f -X POST -H 'Content-Type: application/json' -d "$2" "$base$1"
}

status_of() {
  api "$base/api/collectors/$1" | jq -r '.status // "missing"' 2>/dev/null || echo missing
}

wait_for() {
  for _ in $(seq 1 150); do
    if [ "$(status_of "$1")" = "$2" ]; then
      echo "$1 is $2"
      return 0
    fi
    sleep 1
  done
  echo "$1 never reached $2 (last: $(status_of "$1"))" >&2
  return 1
}

# Delivered event ids in a relay's AMA spool (one envelope per line).
spooled() {
  rm -rf "$work/spool-$1"
  "${compose[@]}" cp "$1:/var/spool/bower/ready" "$work/spool-$1" >/dev/null 2>&1 || true
  cat "$work/spool-$1"/*.jsonl 2>/dev/null | jq -r '.eventId' || true
}

wait_spooled() {
  for _ in $(seq 1 120); do
    if [ "$(spooled "$1" | grep -c "^$2-")" -ge "$3" ]; then
      return 0
    fi
    sleep 1
  done
  echo "$1 spooled $(spooled "$1" | grep -c "^$2-") of $3 events from $2" >&2
  return 1
}

send() {
  local edge=$1 id=$2
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  docker run --rm --network "container:bower-relay-e2e-$edge" curlimages/curl:8.11.1 -sS -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' http://127.0.0.1:4319/v1/events -d "$(jq -n --arg id "$id" --arg now "$now" '{
      schemaVersion: "1.0.0", eventId: $id, eventOriginalId: $id, timeGenerated: $now,
      eventCategory: "authentication", eventType: "authentication_failure", eventAction: "authentication.attempt",
      eventResult: "failure", eventOutcomeReason: "InvalidPassword",
      application: {name: "RelayE2E", environment: "e2e"}, actor: {username: "relay-e2e"},
      source: {ipAddress: "192.0.2.10"}, request: {correlationId: $id}}')"
}

send_batch() {
  local edge=$1 from=$2 to=$3
  for index in $(seq "$from" "$to"); do
    code="$(send "$edge" "$edge-$index")"
    test "$code" = 202 || { echo "$edge-$index answered $code" >&2; return 1; }
  done
}

# PKI: one CA for the relay listeners, one self-signed client certificate per downstream.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=Bower relay e2e CA" -keyout "$work/ca.key" -out "$work/relay-ca.pem" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=bower-management" \
  -keyout "$work/relay.key" -out "$work/relay.csr" 2>/dev/null
printf 'subjectAltName=DNS:bower-management\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' >"$work/relay.ext"
openssl x509 -req -in "$work/relay.csr" -CA "$work/relay-ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
  -days 2 -extfile "$work/relay.ext" -out "$work/relay.crt" 2>/dev/null
for edge in edge-cs edge-rs; do
  mkdir -p "$work/$edge"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$edge" \
    -keyout "$work/$edge/client.key" -out "$work/$edge/client.crt" -addext extendedKeyUsage=clientAuth 2>/dev/null
  cp "$work/relay-ca.pem" "$work/$edge/"
  # Local HTTP is loopback-only; authorize exactly the synthetic identity used by
  # send(). Enrolment approval does not grant producer identity authorization.
  jq -n '[{producer: "anonymous", application: {name: "RelayE2E", environment: "e2e"},
    source: {ipAddress: "192.0.2.10"}}]' >"$work/$edge/producer-scopes.json"
done
pin() { openssl x509 -in "$work/$1/client.crt" -noout -fingerprint -sha256 | cut -d= -f2; }
for relay in relay-cs relay-rs; do
  mkdir -p "$work/$relay"
  cp "$work/relay.crt" "$work/relay.key" "$work/$relay/"
done
# Crossed runtimes: the Rust downstream uses the C# relay and the C# downstream the Rust relay.
jq -n --arg pin "$(pin edge-rs)" '{downstreams: [{collectorId: "edge-rs", certificateSha256: $pin}]}' >"$work/relay-cs/downstreams.json"
jq -n --arg pin "$(pin edge-cs)" '{downstreams: [{collectorId: "edge-cs", certificateSha256: $pin}]}' >"$work/relay-rs/downstreams.json"
grep -h -v -e '^-----' -e '^$' "$work"/*.key "$work"/edge-*/client.key >>"$work/secrets"

"${compose[@]}" up -d bower-management
for _ in $(seq 1 30); do
  api -f "$base/health" >/dev/null 2>&1 && break
  sleep 1
done

for id in relay-cs relay-rs edge-cs edge-rs; do
  token="$(post /api/enrolment-tokens \
    "{\"environment\":\"e2e\",\"collectorId\":\"$id\",\"reason\":\"CI relay e2e\",\"expiresInHours\":1}" \
    | jq -r .token)"
  printf '%s\n' "$token" >>"$work/secrets"
  printf '%s\n' "$token" >"$work/$id/enrolment-token"
done
chmod 755 "$work"/relay-* "$work"/edge-*
chmod 644 "$work"/relay-*/* "$work"/edge-*/*

"${compose[@]}" up -d relay-cs relay-rs
for id in relay-cs relay-rs; do
  wait_for "$id" Pending
  post "/api/approvals/$id/approve" '{"reason":"CI relay e2e approval"}' >/dev/null
done

# The downstreams have no route to management: enrolment and heartbeats cross the relays.
"${compose[@]}" up -d edge-cs edge-rs
for id in edge-cs edge-rs; do
  wait_for "$id" Pending
  post "/api/approvals/$id/approve" '{"reason":"CI relay e2e approval"}' >/dev/null
done
for id in relay-cs relay-rs edge-cs edge-rs; do
  wait_for "$id" Active
done

send_batch edge-cs 1 5
send_batch edge-rs 1 5
wait_spooled relay-rs edge-cs 5
wait_spooled relay-cs edge-rs 5

# Relays down: the downstreams keep accepting and hold the events in their own queues.
"${compose[@]}" stop relay-cs relay-rs
send_batch edge-cs 6 10
send_batch edge-rs 6 10
"${compose[@]}" start relay-cs relay-rs
wait_spooled relay-rs edge-cs 10
wait_spooled relay-cs edge-rs 10
sleep 3

# Exactly once at the destination, still attributed to the downstream that redacted them.
for pair in relay-rs:edge-cs relay-cs:edge-rs; do
  relay="${pair%%:*}"
  edge="${pair##*:}"
  ids="$(spooled "$relay")"
  test "$(grep -c "^$edge-" <<<"$ids")" = 10
  test -z "$(sort <<<"$ids" | uniq -d)"
  test "$(cat "$work/spool-$relay"/*.jsonl | jq -r '.collector.id' | sort -u)" = "$edge"
done

# Relay status counts the downstream's events; the downstream delivered all of them.
relay_status() { api -f "http://127.0.0.1:$1/v1/status"; }
test "$(relay_status 4319 | jq '.relay.downstreams[] | select(.collectorId == "edge-rs") | .accepted')" -ge 5
test "$(relay_status 4329 | jq '.relay.downstreams[] | select(.collectorId == "edge-cs") | .accepted')" -ge 5
for edge in edge-cs edge-rs; do
  queue="$(docker run --rm --network "container:bower-relay-e2e-$edge" curlimages/curl:8.11.1 -sf http://127.0.0.1:4319/v1/status | jq .queue)"
  test "$(jq '.delivered' <<<"$queue")" = 10
  test "$(jq '.queued + .retrying + .uploading + .deadLettered' <<<"$queue")" = 0
done

if "${compose[@]}" logs --no-color 2>&1 | grep -q -F -f "$work/secrets"; then
  echo "A token or private key appeared in a container log." >&2
  exit 1
fi
if "${compose[@]}" logs --no-color 2>&1 | grep -q "PRIVATE KEY"; then
  echo "Private key material appeared in a container log." >&2
  exit 1
fi
echo "Relay e2e passed: C# and Rust downstreams enrolled and delivered exactly once through the other runtime's relay."
