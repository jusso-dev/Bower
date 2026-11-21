// Microsoft Sentinel workbook for Bower security operations and collector pipeline health.
// Source definition: Solutions/Bower/Workbooks/BowerSecurityOperations.json.
targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace with Microsoft Sentinel and BowerSecurity_CL.')
param workspaceName string

@description('Azure region matching the Log Analytics workspace.')
param location string = resourceGroup().location

@description('Display name for the Microsoft Sentinel workbook.')
param workbookDisplayName string = 'Bower Security Operations and Pipeline Health'

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

var workbookId = guid(workspace.id, 'bower-security-operations-workbook')

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    serializedData: loadTextContent('../../Solutions/Bower/Workbooks/BowerSecurityOperations.json')
    version: '1.0'
    sourceId: workspace.id
    category: 'sentinel'
  }
}

output workbookId string = workbook.id
output workbookDisplayName string = workbook.properties.displayName
