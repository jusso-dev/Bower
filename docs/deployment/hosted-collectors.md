# Hosted collectors and application producers

The container and Web App examples on this page use the C# collector image.
They configure Kestrel's TLS certificate settings; do not substitute the Rust
image without a separately configured TLS termination and validation.

Choose the host based on the delivery guarantee you need:

| Host | Use | Queue and authentication |
| --- | --- | --- |
| Docker on an Azure VM | A durable single collector for applications on that host or a trusted container network. | [Compose example](../../deploy/docker/hosted/compose.yaml) uses a local disk-backed Docker volume, TLS, a file-backed ingest token, producer scopes and the VM's managed identity. |
| Kubernetes, including AKS | A single collector with a persistent block volume and workload identity. | [Kubernetes template](../../deploy/kubernetes/deployment.yaml) uses one replica, a PVC, TLS, a secret and default-deny producer scopes. Configure the CSI driver for Azure Disk and workload identity before applying it. |
| Azure Web App for Containers | Private, single-instance pilot or best-effort intake. | [Web App template](../../deploy/azure-webapp/main.bicep) uses a system-assigned managed identity and a Key Vault reference for the ingest token. Its local queue is **ephemeral**: recycling or replacing the instance can lose already accepted events. It is not a durable production collector. |
| [Azure Functions](azure-function.md) | Secretless Entra-authenticated application intake without an operated queue. | Producers use their managed identities and the `Bower.Producer` app role. A response is returned only after Logs Ingestion accepts the batch; there is no durable queue or ledger. |

A collector's managed identity is the **outbound** identity for the Logs Ingestion
API. Grant `Monitoring Metrics Publisher` on the specific DCR, not Contributor
on the subscription. It does not authenticate producers. The HTTP collector
uses its ingest bearer token and producer scopes; the Functions collector validates
Entra tokens and producer scopes. Use separate credentials and scopes per trust
domain. A queue acknowledgement or Logs Ingestion response is not proof that an
event is queryable in Sentinel: query the destination to verify it.

## Private Azure Web App pilot

The Bicep template is plan-only until explicitly deployed. It creates one Linux
App Service instance, disables public access, creates a private endpoint and DNS
zone group, requires HTTPS, disables FTP and SCM basic publishing credentials, and
grants the site's system-assigned identity access to one DCR and one existing
Key Vault secret. No secret value is a template parameter or output. Inline
producer scopes default to an empty array, which denies all events. All callers
share the token's producer ID, `default`, and any holder can assert any tuple
granted to that ID. Use separate collectors or the Entra-authenticated Functions
collector when producers need separate attribution authority.

The site deliberately disables App Service shared `/home` storage. SQLite's WAL
and locking requirements are not established on that network filesystem, and the
container filesystem is lost on replacement or recycle. A 202 means the event was
queued locally, not that Sentinel received it. Use Docker on a suitable local disk
or Kubernetes with a single-writer block volume when durable buffering is needed.
Do not scale this Web App out or use deployment slots as shared queue writers.

Before planning, provide:

1. A reviewed collector image pinned by digest, built **with the
   unresolved Key Vault reference rejection in `CollectorSettings`**. Older images
   may treat an unresolved reference string as an ingest credential. The image
   must also support `BOWER_PRODUCER_SCOPES_JSON`; do not use an older image with
   this template. For a private Azure Container Registry using registry RBAC,
   supply `registryResourceId`; the template grants the site's identity
   `AcrPull` on that registry and configures managed-identity pull. Otherwise the
   image must be public. Initial image pull may need a restart after role
   propagation.
2. A DCR and DCE from [Azure ingestion setup](logs-ingestion-api.md), plus an
   existing Key Vault using Azure RBAC and a strong random ingest-token secret.
   The deployment identity needs permission to create role assignments on that
   DCR and secret and to join the private-endpoint subnet and DNS zone.
3. A reviewed JSON array of exact producer tuples for producer `default`, using
   [producer scopes](../security/producer-scopes.md). This authorization metadata
   is not a secret, but is visible in deployment history. The default `[]`
   admits no events. Changes take effect on restart.
4. An existing private-endpoint subnet and `privatelink.azurewebsites.net` private
   DNS zone linked to the producers' VNets. Private DNS and routing must resolve
   the Web App's normal `*.azurewebsites.net` host name to the private endpoint.
   Producers must use that normal HTTPS host name, which the App Service TLS
   certificate covers. The site also needs outbound access to its image registry,
   Entra, Key Vault and the DCE; arrange VNet integration and DNS separately when
   any of those resources restrict public egress. A private inbound endpoint alone
   does not make outbound traffic private.

Review changes without applying them:

```bash
az bicep build --file deploy/azure-webapp/main.bicep --stdout > /dev/null
az deployment group what-if --resource-group <collector-rg> \
  --template-file deploy/azure-webapp/main.bicep \
  --parameters appName=<unique-name> collectorImage=<image-by-digest> \
    dcrResourceId=<dcr-resource-id> logsIngestionEndpoint=<https-dce-endpoint> \
    vaultResourceId=<vault-resource-id> ingestSecretName=<secret-name> \
    producerScopesJson="$(cat producer-scopes.json)" \
    privateEndpointSubnetId=<subnet-resource-id> privateDnsZoneId=<private-dns-zone-id>
```

After explicit approval to apply, use `az deployment group create` with the same
reviewed parameters. Azure what-if may mark the role assignments unsupported
because the system-assigned principal does not exist until the site is created;
inspect the module scopes before applying and verify the resulting assignments.
Ensure the Key Vault reference resolves before allowing
producers to send: role propagation can take time. The collector fails startup
if App Service passes an unresolved `@Microsoft.KeyVault(...)` string as the
token. Resolve Key Vault networking and role assignment failures; do not work
around them by supplying a predictable token. Check `/health/live` over the
private endpoint, submit a controlled event, and query `BowerSecurity_CL` for its
ID. Key Vault references without a version can be cached by App Service; plan a
controlled refresh/restart and coordinated producer rotation. The single-token
setting does not accept old and new tokens concurrently, so arrange a cutover
with producer buffering and retries.

## Docker on an Azure VM

Use a dedicated Azure VM or host for this collector: other containers that can
reach the VM managed-identity endpoint may also obtain its permissions. Assign
only DCR-scoped publishing to that identity. The Compose example listens with
HTTPS, publishes only to host loopback, drops capabilities, uses a read-only root
filesystem, and keeps the queue in a local Docker volume. Containers attached to
its `intake` network can reach `bower:4319`; issue a certificate whose SAN matches
the name clients actually use and install its issuing CA in each producer.
Use a separately controlled TLS proxy or private network route for remote hosts;
do not publish the collector directly to the Internet.

Provide the image digest, DCE and DCR IDs, collector ID, environment, and paths
for the PEM certificate, unencrypted private key, ingest token and producer
scopes. The private key and token must come from your approved secret-management
process, be readable by container UID/GID 1654, and remain outside the repository.
Populate exact scopes for producer `default` as described in
[producer scopes](../security/producer-scopes.md). The template mounts these files
read-only. An empty scopes array denies all producers. Use a local filesystem on a
managed disk with enough queue and WAL headroom; do not put SQLite on NFS or SMB.
The Docker volume survives a container restart, not disk loss. Configure backups,
monitor free space, and test restore on a replacement host.

Review the Compose model without printing secret values and apply only when
requested:

```bash
docker --context <explicit-context> compose -f deploy/docker/hosted/compose.yaml config --quiet
docker --context <explicit-context> compose -f deploy/docker/hosted/compose.yaml up -d
```

Compose paths refer to the Docker **host**, including when using a remote context.
Protect the TLS key and token on that host, rotate both, and reload/restart the
collector after certificate or scope changes. Publish no Docker socket to the
collector. A host loopback port does not make the shared container network safe
from other containers that can join it.

## Kubernetes and AKS

The Kubernetes template starts with one `Recreate` replica, a default-deny scopes
ConfigMap, a `ReadWriteOnce` PVC, a ClusterIP service, non-root execution, a
read-only root filesystem and a same-namespace producer NetworkPolicy. Replace
the image placeholder with a verified digest and provision the `bower-ingest`
secret (`ingest-token` key), `bower-intake-tls` TLS secret and reviewed producer
scopes before rollout. The certificate must cover the service DNS name and
producers must trust its CA. Kubelet HTTPS probes do not verify the certificate;
clients must verify it normally. Treat pod labels and NetworkPolicy as network
controls, not authentication. Do not let untrusted workloads assign the producer
label, read the secret, or join the trusted namespace. NetworkPolicy requires a
CNI that enforces it; the template permits outbound DNS and HTTPS broadly, so use
an egress firewall or proxy if narrower destination control is required.

For an existing installation, provision the TLS secret and scopes first and
switch producers to HTTPS as part of a coordinated rollout. The template now
uses HTTPS and denies events without a matching scope; applying it unchanged to
an older HTTP installation can interrupt intake.

On AKS use an Azure Disk CSI-backed, single-writer block volume formatted with a
supported local filesystem; do not put the SQLite queue on Azure Files. Configure
Microsoft Entra workload identity for the service account and grant that identity
`Monitoring Metrics Publisher` only on the DCR. Set the DCE and immutable DCR ID
in the `bower-azure` ConfigMap. The single replica and `Recreate` strategy prevent
simultaneous writers in this deployment. `ReadWriteOnce` alone does not prevent
another pod on the same node from mounting the claim: restrict PVC access and,
where the CSI driver supports it, use `ReadWriteOncePod`. Do not attach the queue
to multiple collectors. Size the
PVC for queue, WAL and free-space reserves, back it up, and test recovery. Scopes
are loaded on startup, so restart after a controlled update.

## Sending from another application

A producer sends a semantic security-event envelope to `POST /v1/events` over
HTTPS with `Authorization: Bearer <ingest token>`. The token must match the
collector's configured credential and the event's application/source tuple must
match its scope. Keep the token in your secret manager, never in source, logs,
command arguments or an image. For a .NET producer, `Bower.Sdk` already supplies
a bounded local HTTP transport; load the token from the producer's secret store
and set `LocalCollector.Endpoint` to the HTTPS origin and `LocalCollector.IngestToken`
in `AddBower`. See [ASP.NET Core instrumentation](../developer-integration/aspnetcore.md)
and [producer scopes](../security/producer-scopes.md). The SDK's buffer is in
memory, not a durable producer outbox. Preserve event IDs across retries and use
an application-owned durable outbox when losing an event on producer restart is
unacceptable. The SDK retries transient failures a bounded number of times and
reports sender status; its initial handoff does not report the eventual HTTP
result. A direct HTTP producer must handle refusals and retries itself. Do not
log request bodies or bearer credentials.

For identity-only producer authentication, use the Functions collector: assign
`Bower.Producer` to the producer's managed identity and request an Entra token for
the Bower Ingest API as described in [Azure Functions](azure-function.md). The
standard queued HTTP collector does not validate Entra producer tokens.

For a producer hosted in another Azure Web App, its own managed identity can read
the HTTP collector's token through a separate Key Vault reference. Grant that
identity `Key Vault Secrets User` at the **specific secret** scope, ensure the
producer can reach the vault, then configure `BOWER_COLLECTOR_TOKEN` as an App
Service Key Vault reference and `BOWER_COLLECTOR_ENDPOINT` as the private HTTPS
origin. Never put the token value in a deployment parameter or log. Configure the
producer's role and references after reviewing their scope:

```bash
az role assignment create --assignee-object-id '<producer-managed-identity-object-id>' \
  --assignee-principal-type ServicePrincipal --role 'Key Vault Secrets User' \
  --scope '<vault-resource-id>/secrets/<ingest-secret-name>' --output none
az webapp config appsettings set --resource-group '<producer-rg>' --name '<producer-web-app>' \
  --settings 'BOWER_COLLECTOR_TOKEN=@Microsoft.KeyVault(SecretUri=https://<vault-name>.vault.azure.net/secrets/<ingest-secret-name>/)' \
             'BOWER_COLLECTOR_ENDPOINT=https://<collector-name>.azurewebsites.net' --output none
```

These commands configure a secret reference, not the secret value. The producer
must resolve the collector's private DNS name, reach its private endpoint, and
reach Key Vault with its identity. Configure the SDK at application startup:

```csharp
string token = builder.Configuration["BOWER_COLLECTOR_TOKEN"]
    ?? throw new InvalidOperationException("Collector token is not configured.");
if (token.TrimStart().StartsWith("@Microsoft.KeyVault", StringComparison.OrdinalIgnoreCase))
    throw new InvalidOperationException("Collector token reference did not resolve.");
string endpoint = builder.Configuration["BOWER_COLLECTOR_ENDPOINT"]
    ?? throw new InvalidOperationException("Collector endpoint is not configured.");

builder.Services.AddBower(options =>
{
    options.Application.Name = "customer-portal";
    options.Application.Environment = "production";
    options.LocalCollector.Endpoint = endpoint;
    options.LocalCollector.IngestToken = token;
});
```

Add an exact `default` producer scope for the event identity this application
emits. Another container can load the token from a read-only secret file into the
same SDK option. Keep the token and the scope limited to the intended producer
trust domain, and coordinate a restart or reload of both sides during rotation.
