// Bower operational monitoring: Azure Monitor log alerts on BowerSecurity_CL health records and
// freshness, a DCR error alert, and optional DCR metric alerts and error logs.
// Deploy into the resource group that holds the workspace and the Bower DCR (deploy/bicep/main.bicep).
// Rules are created DISABLED by default; enable them only after validating in the target tenant.
// Alert catalogue, thresholds and runbooks: docs/production-readiness/06-monitoring-and-runbooks.md.
targetScope = 'resourceGroup'

@description('Region of the alert rules. Use the workspace region.')
param location string = resourceGroup().location

@description('Log Analytics workspace (Microsoft Sentinel) name holding BowerSecurity_CL, in this resource group.')
param workspaceName string

@description('Bower data collection rule name in this resource group. Empty skips the DCR error alert, error logs and metric alerts.')
param dataCollectionRuleName string = ''

@description('Tags added to every alert rule and the diagnostic setting.')
param tags object = {}

@description('Prefix for alert rule names.')
@minLength(3)
@maxLength(40)
param namePrefix string = 'bower'

@description('Create the rules enabled. Default false: review queries and thresholds against the tenant first.')
param enabled bool = false

@description('Existing action group resource IDs notified by every rule. Empty: alerts are recorded in Azure Monitor only.')
param actionGroupResourceIds array = []

@description('How often each log alert runs. One minute is not offered: Azure refuses these queries (arg_max, mv-expand, union, join) and absence windows longer than six hours at that frequency.')
@allowed([
  'PT5M'
  'PT10M'
  'PT15M'
])
param evaluationFrequency string = 'PT5M'

@description('Look-back for rules that find the newest health record per collector. Must cover at least two health intervals.')
param healthWindow string = 'PT30M'

@description('Look-back for absence rules. A collector or source silent for longer than this drops out of the window unless listed in expectedCollectorIds.')
param absenceWindow string = 'P2D'

@description('Collector IDs that must keep sending health records. Listed collectors alert even when they never reported in absenceWindow.')
param expectedCollectorIds array = []

@description('Minutes without a newly ingested collector_health record before a collector is reported missing. At least three health intervals.')
@minValue(2)
param healthMissingMinutes int = 15

@description('Oldest undelivered event age, in seconds, that counts as a backlog.')
@minValue(60)
param backlogAgeSeconds int = 900

@description('Health record arrival lag, in minutes, that shows delivery was delayed.')
@minValue(1)
param deliveryLagMinutes int = 15

@description('Undelivered data as a percentage of BOWER_QUEUE_MAX_BYTES that counts as storage pressure. Keep it below 50: the queue file reaches its page limit before the logical cap.')
@minValue(1)
@maxValue(100)
param storageUsedPercent int = 40

@description('Queue database size as a percentage of its SQLite page limit that counts as storage pressure.')
@minValue(1)
@maxValue(100)
param queueFileUsedPercent int = 70

@description('Default minutes without new security events from a collector and application/environment before it is reported silent at the destination.')
@minValue(5)
param sourceSilenceMinutes int = 60

@description('Per-source silence allowances: [{ application, environment, maximumSilenceMinutes }].')
param sourceSilenceOverrides array = []

@description('New syslog connections per health interval above which a listener reports connection churn.')
@minValue(0)
param syslogChurnPerInterval int = 5

@description('Create DCR metric alerts (dropped rows or columns, transformation errors, error responses, no ingestion requests).')
param createDcrMetricAlerts bool = true

@description('Minutes with no Logs Ingestion request at the DCR before the fleet-wide no-ingestion metric alert fires.')
@minValue(5)
param noIngestionMinutes int = 30

@description('Send DCR ingestion error logs (DCRLogErrors) to the workspace. Required by the dcr-errors rule.')
param enableDcrErrorLogs bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = if (!empty(dataCollectionRuleName)) {
  name: empty(dataCollectionRuleName) ? 'unused' : dataCollectionRuleName
}

var dcrResourceId = empty(dataCollectionRuleName) ? '' : dataCollectionRule.id

var healthRules = [
  {
    name: 'collector-health-missing'
    displayName: 'Bower collector health record missing'
    description: 'No collector_health record ingested from a collector recently: collector or host down, or delivery to Sentinel failing. Runbook: R1.'
    severity: 1
    windowSize: absenceWindow
    dimensions: ['CollectorId']
    skipQueryValidation: false
    query: replace(replace(loadTextContent('queries/collector-health-missing.kql'), '__MISSING_MINUTES__', string(healthMissingMinutes)), '__EXPECTED_COLLECTORS__', string(expectedCollectorIds))
  }
  {
    name: 'dead-letters'
    displayName: 'Bower events set aside (dead-lettered)'
    description: 'A collector reports dead-lettered events. They are not delivered until an audited replay. Runbook: R3.'
    severity: 2
    windowSize: healthWindow
    dimensions: ['CollectorId']
    skipQueryValidation: false
    query: loadTextContent('queries/dead-letters.kql')
  }
  {
    name: 'queue-backlog'
    displayName: 'Bower old queued events'
    description: 'Oldest undelivered event or health record arrival lag above the threshold. Runbook: R4.'
    severity: 2
    windowSize: healthWindow
    dimensions: ['CollectorId']
    skipQueryValidation: false
    query: replace(replace(loadTextContent('queries/queue-backlog.kql'), '__BACKLOG_SECONDS__', string(backlogAgeSeconds)), '__LAG_MINUTES__', string(deliveryLagMinutes))
  }
  {
    name: 'queue-storage'
    displayName: 'Bower queue storage pressure'
    description: 'Queue file near its page limit, undelivered data near BOWER_QUEUE_MAX_BYTES, delivery backpressure, or intake refused for capacity. Runbook: R5.'
    severity: 2
    windowSize: healthWindow
    dimensions: ['CollectorId']
    skipQueryValidation: false
    query: replace(replace(loadTextContent('queries/queue-storage.kql'), '__STORAGE_PERCENT__', string(storageUsedPercent)), '__FILE_PERCENT__', string(queueFileUsedPercent))
  }
  {
    name: 'source-overdue'
    displayName: 'Bower expected source silent (collector view)'
    description: 'An application/environment in BOWER_SOURCE_EXPECTATIONS is silent or never seen. Runbook: R6.'
    severity: 2
    windowSize: healthWindow
    dimensions: ['CollectorId', 'Source']
    skipQueryValidation: false
    query: loadTextContent('queries/source-overdue.kql')
  }
  {
    name: 'destination-freshness'
    displayName: 'Bower source silent at the destination'
    description: 'No new security events in BowerSecurity_CL from a collector and application/environment that sent recently. Runbook: R6.'
    severity: 2
    windowSize: absenceWindow
    dimensions: ['CollectorId', 'Source']
    skipQueryValidation: false
    query: replace(replace(loadTextContent('queries/destination-freshness.kql'), '__SILENCE_MINUTES__', string(sourceSilenceMinutes)), '__SILENCE_OVERRIDES__', string(sourceSilenceOverrides))
  }
  {
    name: 'source-transport-errors'
    displayName: 'Bower source loss indicators'
    description: 'Syslog connection refusals, TLS failures, framing or parse errors, drops or churn; Windows Event Log read errors, gaps or failed state. Runbook: R7.'
    severity: 3
    windowSize: healthWindow
    dimensions: ['CollectorId', 'Source']
    skipQueryValidation: false
    query: replace(loadTextContent('queries/source-transport-errors.kql'), '__SYSLOG_CHURN__', string(syslogChurnPerInterval))
  }
]

var dcrRules = empty(dataCollectionRuleName) ? [] : [
  {
    name: 'dcr-errors'
    displayName: 'Bower DCR or workspace ingestion errors'
    description: 'Azure Monitor reported Logs Ingestion errors for the Bower DCR or workspace ingestion warnings. Runbook: R2.'
    severity: 2
    windowSize: healthWindow
    dimensions: ['Source']
    // DCRLogErrors exists only after the first error is written.
    skipQueryValidation: true
    query: replace(loadTextContent('queries/dcr-errors.kql'), '__DCR_RESOURCE_ID__', toLower(dcrResourceId))
  }
]

var rules = concat(healthRules, dcrRules)

resource alertRules 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = [for rule in rules: {
  name: '${namePrefix}-${rule.name}'
  location: location
  kind: 'LogAlert'
  tags: union(tags, {
    'bower-alert': rule.name
  })
  properties: {
    displayName: rule.displayName
    description: rule.description
    severity: rule.severity
    enabled: enabled
    evaluationFrequency: evaluationFrequency
    windowSize: rule.windowSize
    scopes: [
      workspace.id
    ]
    targetResourceTypes: [
      'Microsoft.OperationalInsights/workspaces'
    ]
    criteria: {
      allOf: [
        {
          query: rule.query
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          dimensions: [for dimension in rule.dimensions: {
            name: dimension
            operator: 'Include'
            values: [
              '*'
            ]
          }]
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: true
    skipQueryValidation: rule.skipQueryValidation
    actions: {
      actionGroups: actionGroupResourceIds
      customProperties: {
        bowerAlert: rule.name
        runbook: 'docs/production-readiness/06-monitoring-and-runbooks.md'
      }
    }
  }
}]

resource dcrErrorLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(dataCollectionRuleName) && enableDcrErrorLogs) {
  name: '${namePrefix}-dcr-errors'
  scope: dataCollectionRule
  properties: {
    workspaceId: workspace.id
    logs: [
      {
        category: 'LogErrors'
        enabled: true
      }
    ]
  }
}

// Metric names as the DCR reports them (az monitor metrics list-definitions --resource <dcr id>).
var metricRules = [
  {
    name: 'dcr-rows-dropped'
    description: 'Azure Monitor dropped Logs Ingestion rows for the Bower DCR. Runbook: R2.'
    severity: 1
    metricName: 'RowsDropped_Count'
    operator: 'GreaterThan'
    threshold: 0
    aggregation: 'Total'
    windowSize: 'PT15M'
    dimensions: []
  }
  {
    name: 'dcr-transformation-errors'
    description: 'The Bower DCR transformation failed for some rows. Runbook: R2.'
    severity: 1
    metricName: 'TransformationErrors_Count'
    operator: 'GreaterThan'
    threshold: 0
    aggregation: 'Count'
    windowSize: 'PT15M'
    dimensions: []
  }
  {
    name: 'dcr-columns-dropped'
    description: 'The Bower DCR dropped columns: the stream or table schema drifted from SentinelSchema.Default. Runbook: R2.'
    severity: 2
    metricName: 'ColumnsDroppedCount'
    operator: 'GreaterThan'
    threshold: 0
    // Count is one sample per request even when nothing is dropped; Maximum is the dropped columns.
    aggregation: 'Maximum'
    windowSize: 'PT15M'
    dimensions: []
  }
  {
    name: 'dcr-request-errors'
    description: 'Logs Ingestion requests to the Bower DCR returned an error response. Runbook: R2.'
    severity: 2
    metricName: 'ApiCallReceived_Count'
    operator: 'GreaterThan'
    threshold: 0
    aggregation: 'Count'
    windowSize: 'PT15M'
    dimensions: [
      {
        name: 'ResponseCode'
        operator: 'Exclude'
        values: [
          '200'
          '202'
          '204'
        ]
      }
    ]
  }
  {
    name: 'dcr-no-ingestion'
    description: 'No Logs Ingestion requests reached the Bower DCR from any collector. Fleet-wide delivery outage or every collector down. Runbook: R1.'
    severity: 1
    metricName: 'ApiCallReceived_Count'
    operator: 'LessThan'
    threshold: 1
    aggregation: 'Count'
    windowSize: 'PT${noIngestionMinutes}M'
    dimensions: []
  }
]

resource metricAlerts 'Microsoft.Insights/metricAlerts@2018-03-01' = [for rule in metricRules: if (!empty(dataCollectionRuleName) && createDcrMetricAlerts) {
  name: '${namePrefix}-${rule.name}'
  location: 'global'
  tags: union(tags, {
    'bower-alert': rule.name
  })
  properties: {
    description: rule.description
    severity: rule.severity
    enabled: enabled
    scopes: [
      dcrResourceId
    ]
    evaluationFrequency: 'PT1M'
    windowSize: rule.windowSize
    autoMitigate: true
    targetResourceType: 'Microsoft.Insights/dataCollectionRules'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          name: rule.name
          metricNamespace: 'Microsoft.Insights/dataCollectionRules'
          metricName: rule.metricName
          operator: rule.operator
          threshold: rule.threshold
          timeAggregation: rule.aggregation
          dimensions: rule.dimensions
        }
      ]
    }
    actions: [for group in actionGroupResourceIds: {
      actionGroupId: group
    }]
  }
}]

output logAlertRuleIds array = [for (rule, index) in rules: alertRules[index].id]
output logAlertRuleNames array = [for rule in rules: '${namePrefix}-${rule.name}']
output metricAlertRuleNames array = (!empty(dataCollectionRuleName) && createDcrMetricAlerts) ? map(metricRules, rule => '${namePrefix}-${rule.name}') : []
