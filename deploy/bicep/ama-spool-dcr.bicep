// Azure Monitor Agent collection of the Bower AMA spool (docs/getting-started/azure-monitor-agent.md).
// A collector with BOWER_OUTPUT=ama-spool writes complete, redacted envelopes as JSON lines to
// <spool>/ready/*.jsonl; this rule tells AMA to read them into the BowerSecurity_CL table that
// main.bicep creates. The stream columns and transform must stay identical to main.bicep's
// Custom-BowerSecurity stream (enforced by tests). Plan-only until explicitly deployed.
targetScope = 'resourceGroup'

@description('Region matching the Log Analytics workspace and the data collection endpoint.')
param location string = resourceGroup().location

@description('Existing Log Analytics workspace name, already holding BowerSecurity_CL from main.bicep.')
param workspaceName string

@description('Resource ID of a data collection endpoint in the same region. Custom log collection by AMA needs one.')
param dataCollectionEndpointId string

@description('Bower resource name prefix.')
@minLength(3)
@maxLength(40)
param namePrefix string = 'bower'

@description('Spool ready files to collect. Defaults cover the Linux packages and the Windows MSI.')
param filePatterns array = [
  '/var/spool/bower/ready/*.jsonl'
  'C:\\ProgramData\\Bower\\spool\\ready\\*.jsonl'
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

resource rule 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: '${namePrefix}-ama-spool-dcr'
  location: location
  properties: {
    description: 'Azure Monitor Agent collection of the Bower AMA spool'
    dataCollectionEndpointId: dataCollectionEndpointId
    streamDeclarations: {
      'Custom-BowerSpool': {
        columns: [
          { name: 'schemaVersion', type: 'string' }
          { name: 'eventId', type: 'string' }
          { name: 'eventOriginalId', type: 'string' }
          { name: 'timeGenerated', type: 'datetime' }
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
          { name: 'labels', type: 'dynamic' }
          { name: 'privacy', type: 'dynamic' }
          { name: 'timeObserved', type: 'datetime' }
          { name: 'eventOutcomeReason', type: 'string' }
          { name: 'target', type: 'dynamic' }
          { name: 'change', type: 'dynamic' }
          { name: 'attributes', type: 'dynamic' }
        ]
      }
    }
    dataSources: {
      logFiles: [
        {
          name: 'bowerSpool'
          streams: ['Custom-BowerSpool']
          filePatterns: filePatterns
          format: 'json'
        }
      ]
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
        streams: ['Custom-BowerSpool']
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
              PrivacyDetected = privacy.detected,
              Labels = labels,
              RawEnvelope = pack_all(),
              TimeObserved = timeObserved,
              EventOutcomeReason = substring(tostring(eventOutcomeReason), 0, 1024),
              Target = target,
              Change = change,
              Attributes = attributes
        '''
      }
    ]
  }
}

output dataCollectionRuleId string = rule.id
