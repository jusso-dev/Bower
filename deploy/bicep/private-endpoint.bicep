targetScope = 'resourceGroup'

@description('Private endpoint name in the subnet resource group.')
param name string

@description('Connection name, preserved when updating an existing endpoint.')
param connectionName string

@description('Full subnet resource ID; the caller scopes this module to that subscription and resource group.')
param subnetId string

@description('Azure Monitor Private Link Scope resource ID, which may be in another subscription.')
param privateLinkScopeId string

@description('The existing virtual network location, resolved by the parent deployment.')
param location string

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: name
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: connectionName
        properties: {
          privateLinkServiceId: privateLinkScopeId
          groupIds: ['azuremonitor']
        }
      }
    ]
  }
}

output privateEndpointId string = privateEndpoint.id
