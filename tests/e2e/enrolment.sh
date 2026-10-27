#!/usr/bin/env bash
# Token enrolment end to end in compose (#109). Needs the CI images bower-management:ci,
# bower-collector:ci and bower-collector-rs:ci, plus jq and openssl on the host.
#
# An administrator creates one token per collector; the C# and Rust collectors enrol with
# them, land in Pending, are approved and become Active on a heartbeat signed with their
# key-bound credential. A used token is refused and audited, and no token appears in any
# container log.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
export BOWER_E2E_DIR="$work"
compose=(docker compose -p bower-e2e -f "$here/../../deploy/docker/compose.enrolment-e2e.yaml" --profile collectors)
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
  docker run --rm --network container:bower-e2e-management curlimages/curl:8.11.1 -sS "$@"
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

"${compose[@]}" up -d bower-management
for _ in $(seq 1 30); do
  api -f "$base/health" >/dev/null 2>&1 && break
  sleep 1
done

for id in edge-cs edge-rs; do
  mkdir -p "$work/$id"
  token="$(post /api/enrolment-tokens \
    "{\"environment\":\"e2e\",\"collectorId\":\"$id\",\"reason\":\"CI enrolment e2e\",\"expiresInHours\":1}" \
    | jq -r .token)"
  printf '%s\n' "$token" >>"$work/secrets"
  printf '%s\n' "$token" >"$work/$id/enrolment-token"
  chmod 755 "$work/$id"
  chmod 644 "$work/$id/enrolment-token"
done

"${compose[@]}" up -d collector-cs collector-rs
for id in edge-cs edge-rs; do
  wait_for "$id" Pending
  post "/api/approvals/$id/approve" '{"reason":"CI enrolment e2e approval"}' >/dev/null
done
for id in edge-cs edge-rs; do
  wait_for "$id" Active
done

# A used token is refused (401) and audited; it never enrols a second collector.
public_key="$(openssl ecparam -name prime256v1 -genkey -noout | openssl ec -pubout 2>/dev/null)"
body="$(jq -n --arg token "$(head -n 1 "$work/edge-cs/enrolment-token")" --arg key "$public_key" \
  '{token: $token, collectorId: "edge-cs", machineName: "ci", environment: "e2e", version: "0",
    configurationHash: "c", policyHash: "p", publicKey: $key}')"
reused="$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "$body" \
  "$base/api/collectors/enrol")"
test "$reused" = 401

audit="$(api -f "$base/api/audit")"
test "$(jq '[.[] | select(.action == "collector.enrolled")] | length' <<<"$audit")" = 2
test "$(jq '[.[] | select(.action == "enrolment-token.refused:used")] | length' <<<"$audit")" = 1
test "$(api -f "$base/api/collector-credentials" | jq '[.[] | select(.status == "active")] | length')" = 2

if "${compose[@]}" logs --no-color 2>&1 | grep -q -F -f "$work/secrets"; then
  echo "An enrolment token appeared in a container log." >&2
  exit 1
fi
echo "Token enrolment e2e passed for the C# and Rust collectors."
