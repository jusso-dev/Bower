// Grants Monitoring Metrics Publisher on exactly one DCR, the only permission the Logs
// Ingestion API needs. Never scoped to the resource group, workspace or subscription.
targetScope = 'resourceGroup'

@description('Existing data collection rule name.')
param dcrName string

@description('Object ID of the identity that uploads to Logs Ingestion.')
param principalId string

var metricsPublisherRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')

resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: dcrName
}

resource ingestionGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, principalId, metricsPublisherRole)
  scope: dcr
  properties: {
    roleDefinitionId: metricsPublisherRole
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: 'Bower Azure Functions collector: Logs Ingestion upload to this DCR only.'
  }
}
