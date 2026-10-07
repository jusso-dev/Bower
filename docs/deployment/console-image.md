# Standalone console image

`deploy/docker/Dockerfile.web` packages the management console as static files on
unprivileged nginx. Entra settings are read at container start, so one image serves
every tenant and environment. The management API image (`Dockerfile.management`)
still bundles the console too; use whichever fits your deployment.

```bash
docker build -f deploy/docker/Dockerfile.web -t bower-web:local .

docker run --rm -p 127.0.0.1:8080:8080 --read-only --tmpfs /tmp --cap-drop ALL \
  -e BOWER_API_UPSTREAM=http://bower-management:4320 \
  -e BOWER_ENTRA_TENANT_ID=<tenant-id> \
  -e BOWER_ENTRA_CLIENT_ID=<spa-client-id> \
  -e BOWER_ENTRA_API_SCOPE=api://<api-client-id>/Bower.Access \
  -e BOWER_ENTRA_REDIRECT_URI=https://bower.example.org \
  bower-web:local
```

Or run the console and API together with
[`compose.console.yaml`](../../deploy/docker/compose.console.yaml).

| Variable | Required | Purpose |
|---|---|---|
| `BOWER_API_UPSTREAM` | Yes | Management API base URL, scheme + host + optional port only. `/api/` is proxied there, so the browser stays same-origin (no CORS). |
| `BOWER_AUTH_MODE` | No | `entra` (default) or `development` (local only; the API rejects it outside Development). |
| `BOWER_ENTRA_TENANT_ID`, `BOWER_ENTRA_CLIENT_ID`, `BOWER_ENTRA_API_SCOPE` | For `entra` | Public SPA settings from the app registrations. |
| `BOWER_ENTRA_REDIRECT_URI` | No | Defaults to the page origin. |
| `BOWER_DNS_RESOLVER` | No | DNS server for the upstream lookup. Defaults to the container's `/etc/resolv.conf` nameserver (Docker's `127.0.0.11`, the cluster DNS in Kubernetes). |

How it works:

- The entrypoint validates every value (no control characters; a strict
  `http(s)://host:port` shape for the upstream, because it is written into the nginx
  config), JSON-encodes the Entra settings into `/config.js`, and renders the nginx
  config into `/tmp`. Nothing secret is involved: these are public client settings.
- nginx listens on 8080 as uid 101, serves hashed assets with long-lived caching and
  everything else `no-store`, falls back to `index.html` for client-side routes, and
  sets the same security headers and CSP as the API.
- The API host is resolved per request, so the console starts and serves pages
  even before the API is reachable (API calls return 502 until it is).
- `/healthz` backs the image `HEALTHCHECK`.

When the API runs behind this proxy, include the upstream host name in the API's
`AllowedHosts` (for example `bower-management`).
