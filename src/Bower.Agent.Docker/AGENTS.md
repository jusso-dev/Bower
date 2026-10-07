# Bower.Agent.Docker instructions

Sidecar host that forwards Docker container security events to a Bower collector.

- Read-only: mount `/var/lib/docker/containers` with `:ro`. Never add Docker socket
  access, `docker exec`, or anything that can change other containers.
- Non-root: uid 1654 on the chiseled image, with only `DAC_READ_SEARCH` (file
  capability on the binary plus `cap_add`). Never add a shell, setuid binaries or
  further capabilities to the image.
- At-least-once: advance the cursor only past lines the collector accepted (2xx),
  definitively rejected (400/413/422), or the sidecar intentionally dropped.
  Back off on 429, 503, 5xx, 401/403 and network errors.
- The ingest token never appears in logs. Cleartext HTTP is allowed only for loopback
  or a single-label Compose service name.
- Exit with a status code on fatal errors (PID 1 aborts can hang).
