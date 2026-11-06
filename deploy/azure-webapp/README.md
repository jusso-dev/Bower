# Private Azure Web App collector

The [hosted collector guide](../../docs/deployment/hosted-collectors.md) covers
prerequisites, plan and deployment commands, producer authentication, private
networking, and recovery limitations. The template is plan-only until explicitly
applied. It requires a C# image that rejects unresolved Key Vault and App
Configuration references anywhere in the ingest token and supports inline producer
scopes.

The App Service queue is ephemeral. Every restart, recycle, setting change or
platform maintenance loses events already answered with 202 but not yet
delivered. This example is suitable for a private pilot or best-effort intake; it
does not provide a durable production queue. Use a single-writer local or block
volume when durability is required.

The required `acknowledgeEphemeralQueue` parameter has no default and accepts only
`true`, so a deployment fails until you accept that loss:

```bash
az deployment group what-if --resource-group <collector-rg> \
  --template-file deploy/azure-webapp/main.bicep \
  --parameters @<reviewed-parameters>.json acknowledgeEphemeralQueue=true
```

`queueMaxBytes` (default 1 GiB) sets `BOWER_QUEUE_MAX_BYTES` to fit the worker's
local disk. A user-assigned identity is created and granted before the site, so
the Key Vault reference can resolve on the first start; the guide shows how to
check the reference status.
