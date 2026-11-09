#!/usr/bin/env bash
# Check every framework helper against the cross-language contract, without network access
# for the helpers themselves: each must turn contract/cases.json into exactly
# contract/expected.jsonl (secrets removed, CR/LF replaced, query strings dropped, only the
# trusted client IP). The main CI checks expected.jsonl itself (AsvsExampleContractTests).
#
#   examples/asvs-logging/check.sh            # every toolchain found on PATH
#   REQUIRE=all examples/asvs-logging/check.sh  # fail if any toolchain is missing
#
# Toolchains: python3, node, go, ruby, php, javac/java (+ Jackson jars, see JACKSON_DIR), dotnet.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cases="$here/contract/cases.json"
expected="$here/contract/expected.jsonl"
events_only=$(mktemp)
classes=""
trap 'rm -rf "$events_only" ${classes:+"$classes"}' EXIT
grep -v '"clientIp"' "$expected" > "$events_only"
failed=0
skipped=()

check() {
  local name=$1 compare=$2; shift 2
  local out
  if ! out=$("$@" 2>&1); then
    echo "FAIL  $name: command failed"; echo "$out" | head -20; failed=1; return
  fi
  if diff <(printf '%s\n' "$out") "$compare" >/dev/null; then
    echo "PASS  $name"
  else
    echo "FAIL  $name: output differs from the contract"; diff <(printf '%s\n' "$out") "$compare" | head -20; failed=1
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

if have python3; then check python "$expected" python3 -I "$here/python/contract.py" "$cases"; else skipped+=(python); fi
if have node; then check node "$expected" node "$here/node/contract.mjs" "$cases"; else skipped+=(node); fi
if have go; then check go "$expected" bash -c "cd '$here/go' && go vet ./... && test -z \"\$(gofmt -l .)\" && go run ./cmd/contract '$cases'"; else skipped+=(go); fi
if have ruby; then check ruby "$expected" ruby "$here/ruby/contract.rb" "$cases"; else skipped+=(ruby); fi
if have php; then check php "$expected" php "$here/php/contract.php" "$cases"; else skipped+=(php); fi
if have javac && [ -n "${JACKSON_DIR:-}" ]; then
  classes=$(mktemp -d)
  check java "$expected" bash -c "javac -d '$classes' -cp '$JACKSON_DIR/*' '$here/java/src/main/java/example/bower/BowerEvents.java' '$here/java/src/test/java/example/bower/Contract.java' && java -cp '$classes:$JACKSON_DIR/*' example.bower.Contract '$cases'"
else
  skipped+=("java (needs javac and JACKSON_DIR with jackson-databind, -core and -annotations jars)")
fi
if have dotnet; then
  check dotnet "$events_only" bash -c "cd '$here/aspnetcore-serilog' && dotnet build -c Release --nologo -v quiet >/dev/null && dotnet bin/Release/net10.0/AsvsSerilogExample.dll contract '$cases'"
else
  skipped+=(dotnet)
fi

for item in "${skipped[@]+"${skipped[@]}"}"; do echo "SKIP  $item"; done
if [ "${REQUIRE:-}" = all ] && [ ${#skipped[@]} -gt 0 ]; then failed=1; fi
exit $failed
