targetScope = 'resourceGroup'

@description('Existing Key Vault name; the vault must use Azure RBAC.')
param vaultName string
@description('Existing ingest-token secret name.')
param secretName string
@description('System-assigned identity object ID of the collector.')
param principalId string

var secretsUserRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: vaultName
}
resource secret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' existing = {
  parent: vault
  name: secretName
}
resource grant 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(secret.id, principalId, secretsUserRole)
  scope: secret
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: secretsUserRole
    description: 'Bower Web App: read only its ingest-token secret.'
  }
}
