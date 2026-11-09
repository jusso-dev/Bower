#!/usr/bin/env bash
# Start a throwaway local Bower collector with the owasp-asvs-app-logging pack, for trying the
# framework examples. Nothing leaves the machine: BOWER_OUTPUT=none, an ephemeral signing key,
# an ephemeral HMAC key and a random ingest token, all under a temporary directory.
#
#   examples/asvs-logging/run-local-collector.sh            # prints BOWER_INGEST_TOKEN, then runs
#   BOWER_COLLECTOR_URL=http://127.0.0.1:4319 BOWER_INGEST_TOKEN=... <run an example>
#   bower tap --collector http://127.0.0.1:4319 --stage redacted     # watch post-redaction events
#
# Needs a Release build: dotnet build Bower.sln -c Release
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="$root/src/Bower.Cli/bin/Release/net10.0/bower"
collector="$root/src/Bower.Collector/bin/Release/net10.0/Bower.Collector"
work=$(mktemp -d "${TMPDIR:-/tmp}/bower-asvs.XXXXXX")
trap 'rm -rf "$work"' EXIT

"$bin" keys generate --out-dir "$work/keys" --name local >/dev/null
"$bin" pack build "$root/packs/owasp-asvs-app-logging" --key "$work/keys/local.key.pem" --out "$work/packs" >/dev/null
head -c 32 /dev/urandom > "$work/hmac.key"
token=$("$bin" token generate)
printf '%s' "$token" > "$work/ingest.token"

echo "BOWER_COLLECTOR_URL=http://127.0.0.1:${PORT:-4319}"
echo "BOWER_INGEST_TOKEN=$token"

export BOWER_LISTEN_URL="http://127.0.0.1:${PORT:-4319}"
export BOWER_QUEUE_PATH="$work/queue.db"
export BOWER_POLICY_DIRECTORY="$root/policies/default"
export BOWER_PACKS="$(ls "$work"/packs/owasp-asvs-app-logging-*.bowerpack)"
export BOWER_PACK_TRUSTED_KEYS="$work/keys/local.pub.pem"
export BOWER_PRIVACY_HMAC_KEY_FILE="$work/hmac.key"
export BOWER_PRIVACY_HMAC_KEY_ID=local
export BOWER_INGEST_TOKEN_FILE="$work/ingest.token"
export BOWER_TAP_ENABLED=true
export BOWER_COLLECTOR_ID=asvs-local
export BOWER_OUTPUT=none
# Development only: accept every identity from this one token. Production collectors use
# BOWER_PRODUCER_SCOPES_FILE or a dedicated trust domain (docs/security/producer-scopes.md).
export BOWER_SINGLE_TRUST_DOMAIN=true
"$collector"
