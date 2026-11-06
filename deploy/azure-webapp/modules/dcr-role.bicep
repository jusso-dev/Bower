targetScope = 'resourceGroup'

@description('Existing data collection rule name.')
param dcrName string
@description('Object ID of the collector\'s user-assigned managed identity.')
param principalId string

var publisherRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')
resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: dcrName
}
resource grant 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, principalId, publisherRole)
  scope: dcr
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: publisherRole
    description: 'Bower Web App: publish to this DCR only.'
  }
}
