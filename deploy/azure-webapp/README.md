# Private Azure Web App collector

The [hosted collector guide](../../docs/deployment/hosted-collectors.md) covers
prerequisites, plan and deployment commands, producer authentication, private
networking, and recovery limitations. The template is plan-only until explicitly
applied. It requires a C# image that rejects unresolved Key Vault references and
supports inline producer scopes.

The App Service queue is ephemeral. This example is suitable for a private pilot
or best-effort intake; it does not provide a durable production queue. Use a
single-writer local or block volume when durability is required.
