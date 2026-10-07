#!/bin/sh
# Renders runtime configuration for the Bower console, then starts nginx.
# Values are public client settings (tenant, client id, scope), never secrets.
set -eu

: "${BOWER_API_UPSTREAM:?set BOWER_API_UPSTREAM, for example http://bower-management:4320}"
BOWER_AUTH_MODE="${BOWER_AUTH_MODE:-entra}"

case "$BOWER_AUTH_MODE" in
  entra)
    : "${BOWER_ENTRA_TENANT_ID:?set BOWER_ENTRA_TENANT_ID}"
    : "${BOWER_ENTRA_CLIENT_ID:?set BOWER_ENTRA_CLIENT_ID}"
    : "${BOWER_ENTRA_API_SCOPE:?set BOWER_ENTRA_API_SCOPE}"
    ;;
  development)
    echo "WARNING: development authentication. The management API rejects it outside Development." >&2
    ;;
  *)
    echo "BOWER_AUTH_MODE must be entra or development." >&2
    exit 1
    ;;
esac

# Strict shape: the value is substituted into nginx.conf, so no spaces, quotes,
# semicolons or braces that could inject directives.
if ! printf '%s' "$BOWER_API_UPSTREAM" | grep -Eq '^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/?$'; then
  echo "BOWER_API_UPSTREAM must look like http://host:port (scheme, host and optional port only)." >&2
  exit 1
fi

# Reject control characters up front (a failing $(...) inside the heredoc below
# would not stop the script).
for value in "$BOWER_AUTH_MODE" "${BOWER_ENTRA_TENANT_ID:-}" "${BOWER_ENTRA_CLIENT_ID:-}" \
  "${BOWER_ENTRA_API_SCOPE:-}" "${BOWER_ENTRA_REDIRECT_URI:-}" "$BOWER_API_UPSTREAM"; do
  if printf '%s' "$value" | grep -q '[[:cntrl:]]'; then
    echo "Configuration values must not contain control characters." >&2
    exit 1
  fi
done

# JSON-encode a value: escape backslashes, quotes and '<'.
json() {
  printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/</\\u003c/g')"
}

mkdir -p /tmp/bower-web
cat > /tmp/bower-web/config.js <<CONFIG
window.__BOWER_CONFIG__ = {
  "authMode": $(json "$BOWER_AUTH_MODE"),
  "apiBaseUrl": "",
  "entraTenantId": $(json "${BOWER_ENTRA_TENANT_ID:-}"),
  "entraClientId": $(json "${BOWER_ENTRA_CLIENT_ID:-}"),
  "entraApiScope": $(json "${BOWER_ENTRA_API_SCOPE:-}"),
  "entraRedirectUri": $(json "${BOWER_ENTRA_REDIRECT_URI:-}")
};
CONFIG

# Strip a trailing slash so proxy_pass keeps the /api/ prefix.
BOWER_API_UPSTREAM="${BOWER_API_UPSTREAM%/}"
export BOWER_API_UPSTREAM
envsubst '${BOWER_API_UPSTREAM}' < /etc/bower-web/nginx.conf.template > /tmp/bower-web/nginx.conf

exec nginx -c /tmp/bower-web/nginx.conf -g 'daemon off;'
