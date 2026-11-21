// One-click Microsoft Sentinel deployment for Bower into an existing Log Analytics workspace.
// Composes the BowerSecurity_CL table/DCE/DCR (optional), replay-safe parsers and scheduled
// analytics rules, OWASP ASVS starter rules (optional), Sentinel pipeline health rules (optional),
// and the Bower Security Operations workbook (optional).
// All analytics rules are created DISABLED by default (deploy/AGENTS.md); validate against live
// workspace data before enabling.
// Regenerate deploy/sentinel/azuredeploy.json with:
//   az bicep build --file deploy/sentinel/deploy-to-azure.bicep --outfile deploy/sentinel/azuredeploy.json
targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace name with Microsoft Sentinel enabled, in this resource group.')
param workspaceName string

@description('Azure region matching the Log Analytics workspace.')
param location string = resourceGroup().location

@description('Resource name prefix for the Data Collection Endpoint and Data Collection Rule.')
@minLength(3)
@maxLength(40)
param namePrefix string = 'bower'

@description('Deploy the BowerSecurity_CL table, Data Collection Endpoint and Data Collection Rule. Set to false if deploy/bicep/main.bicep is already deployed.')
param deployIngestionInfrastructure bool = true

@description('Deploy the OWASP ASVS starter scheduled analytics rules (password spray, privilege change, after-hours admin, mass export, log silence).')
param deployAsvsAnalytics bool = true

@description('Deploy the Microsoft Sentinel collector health and source silence analytics rules.')
param deploySentinelHealthRules bool = true

@description('Deploy the Bower Security Operations and Pipeline Health Microsoft Sentinel workbook.')
param deployWorkbook bool = true

@description('Create analytics rules enabled. Keep false until rules are validated against this workspace.')
param enableRules bool = false

@description('Scopes detection keys and rule names to this deployment. Lowercase letters, digits and hyphens.')
@minLength(1)
@maxLength(32)
param detectionKeyScope string = 'default'

@description('IANA time zone for business hours in the ASVS after-hours administrative action rule.')
param timeZone string = 'Australia/Sydney'

@description('Display name for the Microsoft Sentinel workbook.')
param workbookDisplayName string = 'Bower Security Operations and Pipeline Health'

module ingestion '../bicep/main.bicep' = if (deployIngestionInfrastructure) {
  name: '${namePrefix}-ingestion'
  params: {
    workspaceName: workspaceName
    location: location
    namePrefix: namePrefix
  }
}

module analytics './analytics/main.bicep' = {
  name: '${namePrefix}-analytics'
  params: {
    workspaceName: workspaceName
    enableRules: enableRules
    detectionKeyScope: detectionKeyScope
  }
  dependsOn: [
    ingestion
  ]
}

module asvs './analytics/asvs.bicep' = if (deployAsvsAnalytics) {
  name: '${namePrefix}-asvs-analytics'
  params: {
    workspaceName: workspaceName
    enableRules: enableRules
    detectionKeyScope: detectionKeyScope
    timeZone: timeZone
  }
  dependsOn: [
    analytics
  ]
}

module healthRules './monitoring/sentinel-health-rules.bicep' = if (deploySentinelHealthRules) {
  name: '${namePrefix}-sentinel-health'
  params: {
    workspaceName: workspaceName
    enabled: enableRules
  }
  dependsOn: [
    ingestion
  ]
}

module workbook './workbook.bicep' = if (deployWorkbook) {
  name: '${namePrefix}-workbook'
  params: {
    workspaceName: workspaceName
    location: location
    workbookDisplayName: workbookDisplayName
  }
  dependsOn: [
    analytics
  ]
}

output parserFunction string = analytics.outputs.parserFunction
output analyticsRuleIds array = analytics.outputs.ruleIds
output asvsRuleIds array = deployAsvsAnalytics ? asvs!.outputs.ruleIds : []
output healthRuleIds array = deploySentinelHealthRules ? healthRules!.outputs.ruleIds : []
output workbookId string = deployWorkbook ? workbook!.outputs.workbookId : ''
output dataCollectionEndpoint string = deployIngestionInfrastructure ? ingestion!.outputs.dataCollectionEndpoint : ''
output dataCollectionRuleImmutableId string = deployIngestionInfrastructure ? ingestion!.outputs.dataCollectionRuleImmutableId : ''
output tableName string = deployIngestionInfrastructure ? ingestion!.outputs.tableName : 'BowerSecurity_CL'
