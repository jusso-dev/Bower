#!/usr/bin/env bash
# Type-check and build the NestJS example in a temporary copy, then print its directory.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/bower-nestjs.XXXXXX")
cp -R "$here"/. "$work"/
cp "$here/../bower-events.mjs" "$work/bower-events.mjs"
cp "$here/../nextjs/lib/bower-events.d.mts" "$work/bower-events.d.mts"
cd "$work"
npm install --ignore-scripts --no-audit --no-fund --loglevel=error
npx tsc -p .
cp bower-events.mjs dist/
echo "$work"
