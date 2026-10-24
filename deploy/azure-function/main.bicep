// Bower Azure Functions collector ("vanilla native hosting"). Plan-only by default: review
// with `az deployment group what-if` before any apply. See docs/deployment/azure-function.md.
//
// Identity-only: no storage keys, connection strings, client secrets or publishing
// credentials. The function's managed identity (system-assigned by default) gets
// Storage Blob Data Owner on its own host storage account and Monitoring Metrics Publisher
// on the one target DCR. Producers authenticate with Entra tokens carrying Bower.Producer.
targetScope = 'resourceGroup'

@description('Azure region for the function app, plan and storage. Flex Consumption must be available there.')
param location string = 'australiaeast'

@description('Bower resource name prefix (lowercase letters, digits and hyphens).')
@minLength(3)
@maxLength(20)
param namePrefix string = 'bower'

@description('Resource ID of the existing data collection rule (for example from deploy/bicep/main.bicep).')
param dcrResourceId string

@description('Logs Ingestion endpoint: the DCE (or DCR) logs ingestion URL, https://...ingest.monitor.azure.com.')
param logsIngestionEndpoint string

@description('DCR input stream name.')
param streamName string = 'Custom-BowerSecurity'

@description('Entra tenant (directory) ID that issues producer tokens.')
param entraTenantId string

@description('Exact token audience: the Bower Ingest API application (client) ID. v2 tokens carry the GUID.')
param entraAudience string

@description('Optional user-assigned identity resource ID used for Logs Ingestion. Empty uses the system-assigned identity.')
param userAssignedIdentityResourceId string = ''

@description('Claim that names producers in producer scopes: oid (service principal object ID) or azp (client ID).')
@allowed([
  'oid'
  'azp'
])
param producerClaim string = 'oid'

@description('Producer scopes JSON array (same format as BOWER_PRODUCER_SCOPES_FILE). Not a secret. Empty denies every event.')
param producerScopesJson string = ''

@description('Optional privacy profile path inside the deployment package, for example config/privacy.yaml.')
param privacyProfilePath string = ''

@description('Optional Log Analytics workspace resource ID for Application Insights. Empty disables Application Insights.')
param applicationInsightsWorkspaceResourceId string = ''

@description('Maximum on-demand instances (Flex Consumption).')
@minValue(1)
@maxValue(1000)
param maximumInstanceCount int = 40

@description('Instance memory size in MB.')
@allowed([
  512
  2048
  4096
])
param instanceMemoryMB int = 2048

@description('Concurrent HTTP executions per instance.')
@minValue(1)
@maxValue(1000)
param httpPerInstanceConcurrency int = 16

@description('Host storage redundancy.')
@allowed([
  'Standard_LRS'
  'Standard_ZRS'
])
param storageSku string = 'Standard_ZRS'

var suffix = uniqueString(resourceGroup().id, namePrefix)
var functionAppName = '${namePrefix}-fn-${suffix}'
var storageName = '${take(toLower(replace(namePrefix, '-', '')), 9)}fn${suffix}'
var packageContainerName = 'app-package'
var useUserAssigned = !empty(userAssignedIdentityResourceId)
var enableApplicationInsights = !empty(applicationInsightsWorkspaceResourceId)
var dcrParts = split(dcrResourceId, '/')
var dcrSubscriptionId = dcrParts[2]
var dcrResourceGroup = dcrParts[4]
var dcrName = last(dcrParts)
var blobDataOwnerRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b')
var metricsPublisherRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: {
    name: storageSku
  }
  properties: {
    // Identity only: Functions host storage uses AzureWebJobsStorage__accountName.
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource packageContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: packageContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${namePrefix}-fn-plan-${suffix}'
  location: location
  kind: 'functionapp'
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  properties: {
    reserved: true
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = if (enableApplicationInsights) {
  name: '${namePrefix}-fn-ai-${suffix}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: applicationInsightsWorkspaceResourceId
    // Entra-only telemetry ingestion; the connection string alone cannot write.
    DisableLocalAuth: true
    IngestionMode: 'LogAnalytics'
  }
}

module dcrInfo 'modules/dcr-reader.bicep' = {
  name: 'bower-fn-dcr-reader-${suffix}'
  scope: resourceGroup(dcrSubscriptionId, dcrResourceGroup)
  params: {
    dcrName: dcrName
  }
}

var baseSettings = [
  { name: 'AzureWebJobsStorage__accountName', value: storage.name }
  // Pinned: the development authentication bypass is refused outside Development.
  { name: 'AZURE_FUNCTIONS_ENVIRONMENT', value: 'Production' }
  { name: 'FUNCTIONS_REQUEST_BODY_SIZE_LIMIT', value: '1048576' }
  { name: 'BOWER_ENTRA_TENANT_ID', value: entraTenantId }
  { name: 'BOWER_ENTRA_AUDIENCE', value: entraAudience }
  { name: 'BOWER_PRODUCER_CLAIM', value: producerClaim }
  { name: 'BOWER_PRODUCER_SCOPES_JSON', value: producerScopesJson }
  { name: 'BOWER_PRIVACY_PROFILE', value: privacyProfilePath }
  { name: 'BOWER_DCE_ENDPOINT', value: logsIngestionEndpoint }
  { name: 'BOWER_DCR_ID', value: dcrInfo.outputs.immutableId }
  { name: 'BOWER_STREAM_NAME', value: streamName }
  { name: 'BOWER_AZURE_CREDENTIAL', value: 'managed-identity' }
  { name: 'BOWER_AZURE_CLIENT_ID', value: useUserAssigned ? reference(userAssignedIdentityResourceId, '2023-01-31').clientId : '' }
  { name: 'BOWER_COLLECTOR_ID', value: functionAppName }
]

var insightsSettings = enableApplicationInsights
  ? [
      { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: insights!.properties.ConnectionString }
      { name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING', value: 'Authorization=AAD' }
    ]
  : []

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: useUserAssigned
    ? {
        type: 'SystemAssigned, UserAssigned'
        userAssignedIdentities: {
          '${userAssignedIdentityResourceId}': {}
        }
      }
    : {
        type: 'SystemAssigned'
      }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientCertEnabled: false
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      appSettings: concat(baseSettings, insightsSettings)
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${packageContainerName}'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: maximumInstanceCount
        instanceMemoryMB: instanceMemoryMB
        triggers: {
          http: {
            perInstanceConcurrency: httpPerInstanceConcurrency
          }
        }
      }
      runtime: {
        name: 'dotnet-isolated'
        version: '10.0'
      }
    }
  }
  dependsOn: [packageContainer]
}

// FTP and SCM basic-auth publishing are off; deploy with Entra (az functionapp deployment / one deploy).
resource ftpPublishing 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'ftp'
  properties: {
    allow: false
  }
}

resource scmPublishing 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'scm'
  properties: {
    allow: false
  }
}

resource storageGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, site.id, blobDataOwnerRole)
  scope: storage
  properties: {
    roleDefinitionId: blobDataOwnerRole
    principalId: site.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Bower Azure Functions collector: host and deployment package storage.'
  }
}

resource insightsGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableApplicationInsights) {
  name: guid(insights.id, site.id, metricsPublisherRole)
  scope: insights
  properties: {
    roleDefinitionId: metricsPublisherRole
    principalId: site.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Bower Azure Functions collector: Entra-authenticated host telemetry only.'
  }
}

module dcrGrant 'modules/dcr-role.bicep' = {
  name: 'bower-fn-dcr-role-${suffix}'
  scope: resourceGroup(dcrSubscriptionId, dcrResourceGroup)
  params: {
    dcrName: dcrName
    principalId: useUserAssigned
      ? reference(userAssignedIdentityResourceId, '2023-01-31').principalId
      : site.identity.principalId
  }
}

output functionAppName string = site.name
output ingestUrl string = 'https://${site.properties.defaultHostName}/v1/events'
output healthUrl string = 'https://${site.properties.defaultHostName}/health'
output systemAssignedPrincipalId string = site.identity.principalId
output ingestionIdentity string = useUserAssigned ? 'user-assigned' : 'system-assigned'
output storageAccountName string = storage.name
