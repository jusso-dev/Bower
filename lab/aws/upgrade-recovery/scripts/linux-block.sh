#!/bin/bash
# Destination outage: drop only outbound HTTPS from the collector (service uid, and the Docker bridge).
set -euo pipefail
if [ '{{MODE}}' = on ]; then
  nft list table inet bower_ws4_outage >/dev/null 2>&1 || nft -f - <<'NFT'
table inet bower_ws4_outage {
  chain outbound { type filter hook output priority 0; policy accept; meta skuid "bower" tcp dport 443 counter drop; meta skuid 1654 tcp dport 443 counter drop; }
  chain forwarded { type filter hook forward priority 0; policy accept; iifname "docker0" tcp dport 443 counter drop; iifname "br-*" tcp dport 443 counter drop; }
}
NFT
else
  nft delete table inet bower_ws4_outage 2>/dev/null || true
fi
echo "{\"mode\":\"{{MODE}}\",\"at\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\",\"present\":$(nft list table inet bower_ws4_outage >/dev/null 2>&1 && echo true || echo false)}"
