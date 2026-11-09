#!/usr/bin/env bash
# Build the Next.js example in a temporary copy (installs its dependencies there, not here).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/bower-nextjs.XXXXXX")
cp -R "$here"/. "$work"/
cp "$here/../bower-events.mjs" "$work/lib/bower-events.mjs"
cd "$work"
npm install --ignore-scripts --no-audit --no-fund --loglevel=error
NEXT_TELEMETRY_DISABLED=1 npx next build
echo "$work"
