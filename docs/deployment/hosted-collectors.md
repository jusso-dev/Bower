# Hosted collectors and application producers

The container and Web App examples on this page use the C# collector image.
They configure Kestrel's TLS certificate settings; do not substitute the Rust
image without a separately configured TLS termination and validation.

Choose the host based on the delivery guarantee you need:

| Host | Use | Queue and authentication |
| --- | --- | --- |
| Docker on an Azure VM | A durable single collector for applications on that host or a trusted container network. | [Compose example](../../deploy/docker/hosted/compose.yaml) uses a local disk-backed Docker volume, TLS, a file-backed ingest token, producer scopes and the VM's managed identity. |
| Kubernetes, including AKS | A single collector with a persistent block volume and workload identity. | [Kubernetes template](../../deploy/kubernetes/deployment.yaml) uses one replica, a PVC, TLS, a secret and default-deny producer scopes. Configure the CSI driver for Azure Disk and workload identity before applying it. |
| Azure Web App for Containers | Private, single-instance pilot or best-effort intake. | [Web App template](../../deploy/azure-webapp/main.bicep) uses a user-assigned managed identity and a Key Vault reference for the ingest token. Its local queue is **ephemeral**: every restart, recycle or replacement can lose already accepted events, and the template refuses to deploy until you acknowledge that. It is not a durable production collector. |
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
creates a dedicated user-assigned identity with access to one DCR and one existing
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

**Queue loss is part of the contract.** The queue is lost on every container
restart: a producer-scope change, token rotation or any other app setting edit,
an image update, a manual restart, and platform maintenance that moves or
recycles the instance. Events already answered with 202 but not yet delivered are
lost without a record. The required `acknowledgeEphemeralQueue` parameter has no
default and accepts only `true`, so a deployment fails until the operator states
that this loss is acceptable; the site carries the tag
`bower-queue: ephemeral-acknowledged`. Producers that cannot tolerate the loss
need their own durable outbox, or a durable collector.

The template sets `BOWER_QUEUE_MAX_BYTES` from `queueMaxBytes`, default
1073741824 (1 GiB), instead of the collector default of 10 GiB. The container
filesystem shares the worker's local disk with the image, and App Service does not
reserve a size for it. By the
[storage-pressure sizing formula](../production-readiness/03-storage-pressure.md#formula),
a 1 GiB cap needs about 3 GiB free on that disk. Lower `queueMaxBytes` on small
plans; the collector's free-space watermarks refuse new events before the disk
fills either way.

Before planning, provide:

1. A reviewed collector image pinned by digest, built **with the
   unresolved reference rejection in `CollectorSettings`**: it refuses an ingest
   token that contains `@Microsoft.KeyVault(` or `@Microsoft.AppConfiguration(`
   anywhere, in any ASCII letter case, whether quoted, prefixed or read from
   `BOWER_INGEST_TOKEN_FILE`. Older images may treat an unresolved (or wrapped)
   reference string as an ingest credential. The image
   must also support `BOWER_PRODUCER_SCOPES_JSON`; do not use an older image with
   this template. For a private Azure Container Registry using registry RBAC,
   supply `registryResourceId`; the template grants the collector identity
   `AcrPull` on that registry and configures managed-identity pull. Otherwise the
   image must be public.
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
    privateEndpointSubnetId=<subnet-resource-id> privateDnsZoneId=<private-dns-zone-id> \
    acknowledgeEphemeralQueue=true
```

Pass `acknowledgeEphemeralQueue=true` only after reading the queue-loss contract
above. Add `queueMaxBytes=<bytes>` to change the queue cap.

After explicit approval to apply, use `az deployment group create` with the same
reviewed parameters. Azure what-if may mark the role assignments unsupported
because the identity's principal ID is not known until it is created; inspect the
module scopes before applying and verify the resulting assignments.

**Identity timing.** The template uses a user-assigned identity, not the site's
system-assigned one, because a system-assigned identity exists only once the site
does: its Key Vault grant can only follow the first start, so that start always
sees an unresolved reference and App Service caches the failure. The user-assigned
identity is created and granted (secret, DCR and registry) before the site, and the
site uses it for Key Vault references (`keyVaultReferenceIdentity`), image pull and
Logs Ingestion (`BOWER_AZURE_CLIENT_ID`). Each grant stays scoped to one secret,
one DCR and one registry. Anyone who can assign this identity to another resource
(`Managed Identity Operator` on it, or Owner) gains those grants, so keep the
identity's resource group as restricted as the site's. Deleting the site does not
delete the identity or its grants: when you remove the pilot, delete the identity
(`az identity delete`) and its three role assignments as well.

Azure RBAC can still take minutes to propagate, so confirm the reference resolved
before producers send. This reads reference status only, never the secret value:

```bash
az rest --method get --query properties.status --output tsv \
  --url "https://management.azure.com$(az webapp show --resource-group <collector-rg> --name <unique-name> --query id --output tsv)/config/configreferences/appsettings/BOWER_INGEST_TOKEN?api-version=2023-12-01"
```

It prints `Resolved` when the reference works. Any other status (for example
`AccessToKeyVaultDenied`) means the collector refused to start: the collector
fails startup if App Service passes an unresolved `@Microsoft.KeyVault(...)` string
as the token. Fix the role assignment or Key Vault networking. App Service caches
reference values (it re-fetches every 24 hours or on a configuration change), so a
restart alone may reuse the cached failure: ask it to re-fetch the references, then
restart and check the status again:

```bash
site=$(az webapp show --resource-group <collector-rg> --name <unique-name> --query id --output tsv)
az rest --method post --url "https://management.azure.com$site/config/configreferences/appsettings/refresh?api-version=2022-03-01"
az webapp restart --resource-group <collector-rg> --name <unique-name>
```
 The portal shows the same status under **Environment variables**
(Key Vault reference column). Do not work around a failure by supplying a
predictable token. Check `/health/live` over the
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
Protect the TLS key and token on that host and rotate both. Kestrel loads the
certificate at startup, so restart the collector after a certificate, token or
scope change (`docker --context <explicit-context> compose -f
deploy/docker/hosted/compose.yaml restart bower`). Publish no Docker socket to the
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

Kestrel loads the certificate at startup, so a renewed certificate (for example
from cert-manager) is not used until the pod restarts. Restart after each renewal,
and after a token or scope change:

```bash
kubectl --context <explicit-context> -n <namespace> rollout restart deployment/bower-collector
kubectl --context <explicit-context> -n <namespace> rollout status deployment/bower-collector
```

With `Recreate`, the old pod stops before the new one starts, so intake pauses
briefly; producers must retry. The readiness and liveness probes use HTTPS without
verifying the certificate, so a ready pod does not prove the certificate is valid
or current; check it from a producer.

### Upgrading an existing Kubernetes installation

The template changed in ways that can stop intake when applied over an older
installation:

| Change | Effect if unprepared |
| --- | --- |
| HTTPS listener, certificate from the `bower-intake-tls` secret | `Recreate` stops the old pod first; the new pod then waits in `ContainerCreating` (`FailedMount`) until the secret exists, so intake is down. HTTP producers fail. |
| Producer scopes from the `bower-producer-scopes` ConfigMap, shipped as `[]` | Applying the file unchanged replaces your scopes with default deny: every event is refused with 403. |
| NetworkPolicy no longer has `namespaceSelector: {}` | Labelled producers in **other** namespaces are cut off; only labelled pods in the collector's namespace can connect. |
| Pod runs as UID/GID 1654 with `fsGroup: 1654`; token and TLS secrets mounted `0440` | Secret files are owned by root. The old `0400` mode let only root read the token, so the non-root collector could not. Now the files are group 1654 and group-readable. Keep `0440` and the `fsGroup` together if you override either; `fsGroup` also changes group ownership on the `bower-data` volume when it mounts. |

Roll out in this order:

1. Back up the queue (see
   [04 backup](../production-readiness/04-upgrade-backup-recovery.md#back-up-a-live-collector)).
2. Create the TLS secret **before** applying. The certificate must cover the
   service name producers use (`bower-collector.<namespace>.svc`):

   ```bash
   kubectl --context <explicit-context> -n <namespace> create secret tls bower-intake-tls \
     --cert=<certificate.pem> --key=<private-key.pem>
   kubectl --context <explicit-context> -n <namespace> get secret bower-intake-tls
   ```

3. In your copy of the manifest, replace the `[]` in the `bower-producer-scopes`
   ConfigMap with the reviewed scopes.
4. If producers run in other namespaces, either move them into the collector's
   namespace or add a reviewed `namespaceSelector` naming each producer namespace
   (for example `kubernetes.io/metadata.name: <producer-namespace>`) alongside the
   `podSelector` in the same `from` entry. Do not restore `namespaceSelector: {}`.
5. Install the issuing CA in every producer and make sure producers buffer and
   retry, because intake pauses during the switch.
6. Apply, then wait for the new pod:

   ```bash
   kubectl --context <explicit-context> -n <namespace> apply -f deployment.yaml
   kubectl --context <explicit-context> -n <namespace> rollout status deployment/bower-collector
   kubectl --context <explicit-context> -n <namespace> get events --field-selector involvedObject.kind=Pod
   ```

   `FailedMount` for `bower-intake-tls` means step 2 was missed: create the secret
   and the pod starts.
7. Switch producers to `https://bower-collector.<namespace>.svc:4319`, send a
   controlled event, and query `BowerSecurity_CL` for its ID.

To roll back, re-apply the previous manifest; the queue on `bower-data` is kept. If the
upgrade also moved to a newer collector image, check the downgrade rules in
[upgrade, backup and recovery](../production-readiness/04-upgrade-backup-recovery.md)
first: an older image may refuse a queue a newer one has migrated. `kubectl apply` does
not delete the new `bower-producer-scopes` ConfigMap or `bower-intake-tls` secret;
leaving them is harmless, or delete them once the rollback is verified.

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
if (token.Contains("@Microsoft.KeyVault(", StringComparison.OrdinalIgnoreCase)
    || token.Contains("@Microsoft.AppConfiguration(", StringComparison.OrdinalIgnoreCase))
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

## Follow-ups

- The Web App collector does not yet report that its queue is ephemeral in
  `/v1/status` or `collector_health`. A collector setting for that is planned in a
  separate change.
