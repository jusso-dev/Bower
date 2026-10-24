// Reads the existing DCR's immutable ID (the Logs Ingestion API path segment). Read-only.
targetScope = 'resourceGroup'

@description('Existing data collection rule name.')
param dcrName string

resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: dcrName
}

output immutableId string = dcr.properties.immutableId
