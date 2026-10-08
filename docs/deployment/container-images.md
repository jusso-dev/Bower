# Container images

The `Images` workflow publishes five images to GitHub Container Registry for
`linux/amd64` and `linux/arm64`:

| Image | Contents |
|---|---|
| `ghcr.io/jusso-dev/bower-collector` | Collector: redaction, policy, durable queue and outputs |
| `ghcr.io/jusso-dev/bower-management` | Management API with the bundled console |
| `ghcr.io/jusso-dev/bower-web` | Standalone console on unprivileged nginx ([details](console-image.md)) |
| `ghcr.io/jusso-dev/bower-sidecar` | Docker sidecar ([details](docker-sidecar.md)) |
| `ghcr.io/jusso-dev/bower-cloud` | Cloud agent for AWS SQS and Google Pub/Sub ([AWS](aws.md), [GCP](gcp.md)) |

## Tags

| Tag | Published when | Use for |
|---|---|---|
| `edge` | every `main` commit whose CI passed | trying the latest build |
| `sha-<commit>` | every `main` commit whose CI passed | pinning an exact build |
| `X.Y.Z`, `X.Y`, `latest` | a `vX.Y.Z` tag is pushed | production |

Pin production deployments by version or digest (`@sha256:…`), not `edge`.

## Supply chain

Each image carries an SPDX SBOM and SLSA provenance from BuildKit, plus a GitHub
build-provenance attestation signed with the workflow's OIDC identity:

```bash
gh attestation verify oci://ghcr.io/jusso-dev/bower-sidecar:edge --owner jusso-dev
docker buildx imagetools inspect ghcr.io/jusso-dev/bower-sidecar:edge --format '{{ json .SBOM }}'
```

## Configuring the published management image

The published `bower-management` image is built without tenant settings. Configure the
API and its bundled console at runtime:

```text
Bower__Entra__TenantId=<tenant-id>
Bower__Entra__Audience=api://<api-client-id>
Bower__Console__ClientId=<spa-client-id>
Bower__Console__ApiScope=api://<api-client-id>/Bower.Access
Bower__Console__RedirectUri=https://bower.example.org   # optional
```

The API serves these public SPA values as `/config.js`. Or run `bower-web` in front
of the API and configure the console there instead.
