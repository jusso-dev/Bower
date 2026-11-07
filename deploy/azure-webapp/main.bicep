// Private, single-instance App Service pilot. The local queue is ephemeral; see README.
targetScope = 'resourceGroup'

@description('Globally unique App Service name, also used as collector ID.')
@minLength(2)
@maxLength(35)
param appName string
@description('Linux collector image, preferably pinned by digest; supply registryResourceId for Azure Container Registry.')
param collectorImage string
@description('Optional Azure Container Registry resource ID for managed-identity image pull. Otherwise the image must be public.')
param registryResourceId string = ''
@description('Existing DCR resource ID, in the same Entra tenant.')
param dcrResourceId string
@description('HTTPS Logs Ingestion endpoint for that DCR.')
param logsIngestionEndpoint string
@description('Existing Key Vault resource ID, in the same Entra tenant, using Azure RBAC.')
param vaultResourceId string
@description('Name of the existing ingest-token secret. The secret value is never a deployment parameter.')
param ingestSecretName string
@description('Existing subnet resource ID for the private endpoint.')
param privateEndpointSubnetId string
@description('Existing privatelink.azurewebsites.net private DNS zone resource ID, linked to client VNets.')
param privateDnsZoneId string
@description('Exact producer identity scopes as a JSON array; empty array denies all producers.')
param producerScopesJson string = '[]'
@description('Region for the App Service and private endpoint.')
param location string = resourceGroup().location
@description('Tags applied to the App Service plan, site and private endpoint.')
param tags object = {}
@description('Linux App Service SKU; must support Always On.')
param sku string = 'B1'
@description('Bower environment stamped on events.')
param environmentName string = 'production'
@description('Required, no default: true accepts that the queue is in the container filesystem and is lost on every restart, recycle, setting change or platform maintenance, including events already answered with 202 but not yet delivered.')
@allowed([true])
param acknowledgeEphemeralQueue bool
@description('Queue cap in bytes. The container filesystem shares the worker local disk, so keep this well below the default 10 GiB.')
@minValue(1048576)
param queueMaxBytes int = 1073741824

var dcrParts = split(dcrResourceId, '/')
var vaultParts = split(vaultResourceId, '/')
var registryParts = split(registryResourceId, '/')
var registrySubscription = empty(registryResourceId) ? subscription().subscriptionId : registryParts[2]
var registryGroup = empty(registryResourceId) ? resourceGroup().name : registryParts[4]
var registryName = empty(registryResourceId) ? '' : registryParts[8]
resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  scope: resourceGroup(dcrParts[2], dcrParts[4])
  name: dcrParts[8]
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  scope: resourceGroup(vaultParts[2], vaultParts[4])
  name: vaultParts[8]
}
// Created and granted before the site, so the Key Vault reference can resolve on the
// first start. A system-assigned identity exists only after the site starts.
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${appName}-id'
  location: location
  tags: tags
}
resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${appName}-plan'
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: sku, capacity: 1 }
  properties: { reserved: true }
}
resource app 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  tags: union(tags, { 'bower-queue-ephemeral-acknowledged': string(acknowledgeEphemeralQueue) })
  kind: 'app,linux,container'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  dependsOn: [tokenGrant, dcrGrant, registryGrant]
  properties: {
    serverFarmId: plan.id
    keyVaultReferenceIdentity: identity.id
    httpsOnly: true
    publicNetworkAccess: 'Disabled'
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'DOCKER|${collectorImage}'
      acrUseManagedIdentityCreds: !empty(registryResourceId)
      acrUserManagedIdentityID: empty(registryResourceId) ? null : identity.properties.clientId
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      appSettings: [
        { name: 'WEBSITES_PORT', value: '4319' }
        { name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE', value: 'false' }
        { name: 'BOWER_LISTEN_URL', value: 'http://0.0.0.0:4319' }
        { name: 'BOWER_COLLECTOR_ID', value: appName }
        { name: 'BOWER_ENVIRONMENT', value: environmentName }
        { name: 'BOWER_OUTPUT', value: 'azure-logs-ingestion' }
        { name: 'BOWER_AZURE_CREDENTIAL', value: 'managed-identity' }
        { name: 'BOWER_AZURE_CLIENT_ID', value: identity.properties.clientId }
        { name: 'BOWER_QUEUE_MAX_BYTES', value: string(queueMaxBytes) }
        { name: 'BOWER_DCE_ENDPOINT', value: logsIngestionEndpoint }
        { name: 'BOWER_DCR_ID', value: dcr.properties.immutableId }
        { name: 'BOWER_STREAM_NAME', value: 'Custom-BowerSecurity' }
        { name: 'BOWER_INGEST_TOKEN', value: '@Microsoft.KeyVault(SecretUri=${vault.properties.vaultUri}secrets/${ingestSecretName}/)' }
        { name: 'BOWER_PRODUCER_SCOPES_JSON', value: producerScopesJson }
      ]
    }
  }
}
resource ftpBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: app
  name: 'ftp'
  properties: { allow: false }
}
resource scmBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: app
  name: 'scm'
  properties: { allow: false }
}
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${appName}-pe'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [{
      name: '${appName}-sites'
      properties: { privateLinkServiceId: app.id, groupIds: ['sites'] }
    }]
  }
}
resource privateDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [{
      name: 'appservice'
      properties: { privateDnsZoneId: privateDnsZoneId }
    }]
  }
}
module dcrGrant './modules/dcr-role.bicep' = {
  name: '${uniqueString(identity.id, dcr.id)}-dcr-grant'
  scope: resourceGroup(dcrParts[2], dcrParts[4])
  params: { dcrName: dcr.name, principalId: identity.properties.principalId }
}
module tokenGrant './modules/secret-role.bicep' = {
  name: '${uniqueString(identity.id, vault.id, ingestSecretName)}-token-grant'
  scope: resourceGroup(vaultParts[2], vaultParts[4])
  params: { vaultName: vault.name, secretName: ingestSecretName, principalId: identity.properties.principalId }
}
module registryGrant './modules/acr-role.bicep' = if (!empty(registryResourceId)) {
  name: '${uniqueString(identity.id, registryResourceId)}-registry-grant'
  scope: resourceGroup(registrySubscription, registryGroup)
  params: { registryName: registryName, principalId: identity.properties.principalId }
}
output appHost string = app.properties.defaultHostName
output identityPrincipalId string = identity.properties.principalId
output privateEndpointId string = privateEndpoint.id
