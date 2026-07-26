targetScope = 'resourceGroup'

@description('Region matching the Log Analytics workspace.')
param location string = resourceGroup().location

@description('Existing Log Analytics workspace name.')
param workspaceName string

@description('Bower resource name prefix.')
@minLength(3)
@maxLength(40)
param namePrefix string = 'bower'

@allowed([
  'Enabled'
  'Disabled'
])
param publicNetworkAccess string = 'Enabled'

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2025-07-01' = {
  parent: workspace
  name: 'BowerSecurity_CL'
  properties: {
    plan: 'Analytics'
    retentionInDays: 30
    totalRetentionInDays: 365
    schema: {
      name: 'BowerSecurity_CL'
      columns: [
        { name: 'TimeGenerated', type: 'dateTime' }
        { name: 'EventId', type: 'string' }
        { name: 'EventOriginalId', type: 'string' }
        { name: 'EventCategory', type: 'string' }
        { name: 'EventType', type: 'string' }
        { name: 'EventAction', type: 'string' }
        { name: 'EventResult', type: 'string' }
        { name: 'EventSeverity', type: 'string' }
        { name: 'ApplicationName', type: 'string' }
        { name: 'ApplicationEnvironment', type: 'string' }
        { name: 'ActorUserId', type: 'string' }
        { name: 'ActorUsername', type: 'string' }
        { name: 'SourceIpAddress', type: 'string' }
        { name: 'CorrelationId', type: 'string' }
        { name: 'PolicyId', type: 'string' }
        { name: 'PolicyVersion', type: 'string' }
        { name: 'PolicyHash', type: 'string' }
        { name: 'ValueScore', type: 'int' }
        { name: 'CollectorId', type: 'string' }
        { name: 'RawEnvelope', type: 'dynamic' }
      ]
    }
  }
}

resource endpoint 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = {
  name: '${namePrefix}-dce'
  location: location
  properties: {
    description: 'Bower Logs Ingestion API endpoint'
    networkAcls: {
      publicNetworkAccess: publicNetworkAccess
    }
  }
}

resource rule 'Microsoft.Insights/dataCollectionRules@2025-07-01' = {
  name: '${namePrefix}-dcr'
  location: location
  kind: 'Direct'
  properties: {
    dataCollectionEndpointId: endpoint.id
    streamDeclarations: {
      'Custom-BowerSecurity': {
        columns: [
          { name: 'schemaVersion', type: 'string' }
          { name: 'eventId', type: 'string' }
          { name: 'eventOriginalId', type: 'string' }
          { name: 'timeGenerated', type: 'dateTime' }
          { name: 'eventCategory', type: 'string' }
          { name: 'eventType', type: 'string' }
          { name: 'eventAction', type: 'string' }
          { name: 'eventResult', type: 'string' }
          { name: 'eventSeverity', type: 'string' }
          { name: 'application', type: 'dynamic' }
          { name: 'actor', type: 'dynamic' }
          { name: 'source', type: 'dynamic' }
          { name: 'request', type: 'dynamic' }
          { name: 'security', type: 'dynamic' }
          { name: 'collector', type: 'dynamic' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'BowerWorkspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Custom-BowerSecurity']
        destinations: ['BowerWorkspace']
        outputStream: 'Custom-BowerSecurity_CL'
        transformKql: '''
          source
          | where schemaVersion == "1.0.0"
          | project
              TimeGenerated = timeGenerated,
              EventId = substring(tostring(eventId), 0, 128),
              EventOriginalId = substring(tostring(eventOriginalId), 0, 256),
              EventCategory = substring(tostring(eventCategory), 0, 128),
              EventType = substring(tostring(eventType), 0, 128),
              EventAction = substring(tostring(eventAction), 0, 128),
              EventResult = substring(tostring(eventResult), 0, 32),
              EventSeverity = substring(tostring(eventSeverity), 0, 32),
              ApplicationName = substring(tostring(application.name), 0, 128),
              ApplicationEnvironment = substring(tostring(application.environment), 0, 64),
              ActorUserId = substring(tostring(actor.userId), 0, 256),
              ActorUsername = substring(tostring(actor.username), 0, 256),
              SourceIpAddress = substring(tostring(source.ipAddress), 0, 64),
              CorrelationId = substring(tostring(request.correlationId), 0, 256),
              PolicyId = substring(tostring(security.policyId), 0, 128),
              PolicyVersion = substring(tostring(security.policyVersion), 0, 32),
              PolicyHash = substring(tostring(security.policyHash), 0, 128),
              ValueScore = toint(security.valueScore),
              CollectorId = substring(tostring(collector.id), 0, 128),
              RawEnvelope = pack_all()
        '''
      }
    ]
  }
  dependsOn: [table]
}

output dataCollectionEndpoint string = endpoint.properties.logsIngestion.endpoint
output dataCollectionRuleImmutableId string = rule.properties.immutableId
output streamName string = 'Custom-BowerSecurity'
output tableName string = table.name
