# Docker sidecar

`Bower.Agent.Docker` is a small container you add to an existing Docker or Compose
stack. It reads the logs of containers you opt in, picks out security events, and
forwards them to a Bower collector. The collector then redacts, validates and applies
policy exactly as it does for SDK events.

```
labelled containers ──json-file logs──▶ bower-sidecar ──HTTPS/token──▶ bower-collector ──▶ Sentinel
                       (read-only)       select + map                    redact + policy
```

## What it forwards

The sidecar is deliberately selective; Bower is not a log shipper.

| Line in a container log | Result |
|---|---|
| A Bower event envelope printed as one JSON line (`schemaVersion`, `eventId`, `eventType`, …) | Forwarded as-is, with `docker.*` labels added |
| SSH `Failed password` / `Failed publickey` / `Invalid user` | `authentication_failure` with username and source IP |
| SSH `maximum authentication attempts exceeded` | `account_lockout` |
| PAM `pam_unix(...:auth): authentication failure` | `authentication_failure` |
| nginx basic auth `password mismatch` / `was not found` | `authentication_failure` |
| Anything else | Dropped at the sidecar and counted |

Mapped events never contain the raw line; they carry a SHA-256 of it plus the
container id, name and image. Event ids derive from container id, log file and byte
offset, so replays after a restart are deduplicated by the collector.

For anything not in the table, have the application print Bower events as JSON on
stdout (see [ASP.NET Core integration](../developer-integration/aspnetcore.md) for the
event shape) — they pass straight through.

## Install into an existing stack

1. Build the image from the Bower repository root:

   ```bash
   docker build -f deploy/docker/Dockerfile.sidecar -t bower-sidecar:local .
   ```

2. Label each container whose logs Bower should read:

   ```yaml
   services:
     ssh-gateway:
       image: example/ssh-gateway
       labels:
         bower.collect: "true"
         bower.application: ssh-gateway   # optional; defaults to the container name
         bower.environment: production    # optional
   ```

3. Merge the sidecar into your stack, pointing it at your collector:

   ```bash
   export BOWER_INGEST_TOKEN=<the collector's ingest token>
   export BOWER_COLLECTOR_URL=http://bower-collector:4319   # or https://collector.example.org
   docker compose -f compose.yaml -f /path/to/bower/deploy/docker/compose.sidecar.yaml up -d
   ```

4. Check it: `docker compose logs bower-sidecar` prints one summary line per pass
   with forwarded, rejected and dropped counts. `docker ps` shows the health check.

Try it all locally first with the demo stack (collector, sidecar, a labelled
"legacy" container and an unlabelled one that is ignored):

```bash
export BOWER_INGEST_TOKEN="$(dotnet run --project src/Bower.Cli -- token generate)"
docker compose -f deploy/docker/compose.sidecar-demo.yaml up --build
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `BOWER_COLLECTOR_URL` | `http://bower-collector:4319` | Collector base URL. With a token, plain HTTP is allowed only for loopback or a single-label Compose service name. |
| `BOWER_INGEST_TOKEN` / `BOWER_INGEST_TOKEN_FILE` | — | Collector ingest token. |
| `BOWER_DOCKER_LABEL` | `bower.collect` | Opt-in label (value must be `true`). |
| `BOWER_DOCKER_READ_EXISTING` | `false` | `true` replays existing log history the first time a container is seen. |
| `BOWER_POLL_SECONDS` | `5` | Poll interval (1–600). Backs off up to 2 minutes under backpressure. |
| `BOWER_SIDECAR_ID` | host name | Identifies the sidecar on forwarded events. |
| `BOWER_ENVIRONMENT` | `production` | Default `application.environment` when the container has no label. |
| `BOWER_DOCKER_ROOT` | `/var/lib/docker/containers` | Mounted Docker container directory. |
| `BOWER_SIDECAR_STATE` | `/var/lib/bower-sidecar/cursors.db` | Durable cursors (keep on a volume). |

## Delivery guarantees

- **At least once.** The cursor for each container advances only past lines the
  collector accepted (`200`/`202`), definitively refused (`400`/`413`/`422`), or the
  sidecar intentionally dropped. On `429`, `503`, `5xx`, `401`/`403` or a network
  error it stops, keeps its position and backs off.
- **Restarts.** Cursors live in SQLite on the `bower-sidecar-state` volume, so a
  restarted sidecar resumes where it stopped.
- **Rotation.** Files are identified by their first bytes, so Docker's
  `max-size`/`max-file` rotation is detected; the rotated file is drained before the
  new one. If a log rotates more than once between passes, the gap is logged.
- **Bounds.** Lines over 64 KiB are counted and skipped; each pass reads at most
  1,000 lines or 4 MiB per container. Docker's 16 KiB partial chunks are reassembled.

## Security model

- **No Docker socket.** The sidecar reads `/var/lib/docker/containers` mounted
  read-only. It cannot list, start, stop or exec containers.
- **Least privilege.** Docker's log files are root-owned, so the process runs as
  uid 0 but with every capability dropped, `no-new-privileges`, and a read-only root
  filesystem.
- **Opt-in only.** Containers without `bower.collect=true` are never read.
- **Token handling.** The ingest token is sent only as a bearer header and is never
  logged.

## Limitations

- Requires the `json-file` logging driver (Docker's default). Containers using
  `local`, `journald`, `syslog` or other drivers are skipped and counted.
- Docker Desktop and OrbStack keep container logs inside their Linux VM; the bind
  mount works when the daemon resolves `/var/lib/docker/containers` inside that VM
  (verified on Docker 29 with the demo stack).
- Rootless Docker and user-namespace remapping store logs elsewhere and map uid 0;
  set `BOWER_DOCKER_ROOT` and permissions accordingly.
