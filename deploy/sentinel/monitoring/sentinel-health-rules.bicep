// Microsoft Sentinel scheduled analytics rules for Bower pipeline health: a collector that stopped
// sending health records, and a source that went silent at the destination. They raise Sentinel
// incidents for the SOC, alongside (not instead of) the Azure Monitor rules in monitoring.bicep.
// Rules are created DISABLED by default. Deploy into the resource group of the Sentinel workspace.
// Runbooks: docs/production-readiness/06-monitoring-and-runbooks.md (R1 and R6).
targetScope = 'resourceGroup'

@description('Log Analytics workspace (Microsoft Sentinel enabled) name in this resource group.')
param workspaceName string

@description('Create the rules enabled. Default false: validate against the tenant first.')
param enabled bool = false

@description('How often each rule runs (Sentinel minimum is five minutes).')
param queryFrequency string = 'PT5M'

@description('Look-back for both rules. Sentinel requires a frequency of at least one hour once the look-back reaches two days.')
param queryPeriod string = 'P1D'

@description('Collector IDs that must keep sending health records; they alert even if never seen in the look-back.')
param expectedCollectorIds array = []

@description('Minutes without a newly ingested collector_health record before a collector is reported missing.')
@minValue(2)
param healthMissingMinutes int = 15

@description('Default minutes without new security events from a collector and application/environment.')
@minValue(5)
param sourceSilenceMinutes int = 60

@description('Per-source silence allowances: [{ application, environment, maximumSilenceMinutes }].')
param sourceSilenceOverrides array = []

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

// Sentinel custom details read string columns.
var missingQuery = '${replace(replace(loadTextContent('queries/collector-health-missing.kql'), '__MISSING_MINUTES__', string(healthMissingMinutes)), '__EXPECTED_COLLECTORS__', string(expectedCollectorIds))}\n| extend LastIngestedText = tostring(LastIngested), MinutesText = tostring(MinutesSinceLastRecord)'
var freshnessQuery = '${replace(replace(loadTextContent('queries/destination-freshness.kql'), '__SILENCE_MINUTES__', string(sourceSilenceMinutes)), '__SILENCE_OVERRIDES__', string(sourceSilenceOverrides))}\n| extend LastIngestedText = tostring(LastIngested), MinutesText = tostring(SilentMinutes)'

resource collectorMissing 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'bower-collector-health-missing')
  kind: 'Scheduled'
  properties: {
    displayName: 'Bower collector health record missing'
    description: 'A Bower collector stopped sending collector_health records: collector or host down, or delivery to Sentinel failing. Security events from it are not arriving either.'
    severity: 'High'
    enabled: enabled
    query: missingQuery
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'DefenseEvasion'
    ]
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    customDetails: {
      CollectorId: 'CollectorId'
      LastIngested: 'LastIngestedText'
      MinutesSilent: 'MinutesText'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Bower collector {{CollectorId}} stopped reporting'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT6H'
        matchingMethod: 'Selected'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: [
          'CollectorId'
        ]
      }
    }
  }
}

resource sourceSilent 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'bower-destination-freshness')
  kind: 'Scheduled'
  properties: {
    displayName: 'Bower source silent at the destination'
    description: 'A collector and application/environment that sent security events recently has sent none for longer than its allowance (firewall or WEC stopped sending, or its path to Bower failed).'
    severity: 'Medium'
    enabled: enabled
    query: freshnessQuery
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'DefenseEvasion'
    ]
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    customDetails: {
      CollectorId: 'CollectorId'
      Source: 'Source'
      LastIngested: 'LastIngestedText'
      MinutesSilent: 'MinutesText'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Bower source {{Source}} on {{CollectorId}} is silent'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT6H'
        matchingMethod: 'Selected'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: [
          'CollectorId'
          'Source'
        ]
      }
    }
  }
}

output ruleIds array = [
  collectorMissing.id
  sourceSilent.id
]
