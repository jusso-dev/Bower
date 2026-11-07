targetScope = 'resourceGroup'

@description('Existing Azure Container Registry name.')
param registryName string
@description('Object ID of the collector\'s user-assigned managed identity.')
param principalId string

var acrPullRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: registryName
}
resource grant 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, principalId, acrPullRole)
  scope: registry
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRole
    description: 'Bower Web App: pull images from this registry.'
  }
}
