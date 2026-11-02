// Replay-safe Bower content for Microsoft Sentinel: the BowerSecurityEvents parser and
// scheduled analytics rules that neither duplicate incidents on at-least-once replays
// nor miss events delayed by destination outages. Reads BowerSecurity_CL as deployed by
// deploy/bicep/main.bicep; changes no table, DCR or stream schema.
// Guide: docs/production-readiness/02-replay-safe-detections.md
targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace with Microsoft Sentinel and BowerSecurity_CL.')
param workspaceName string

@description('Create the rules enabled. Keep false until the rules are validated against this workspace.')
param enableRules bool = false

@description('Minutes between scheduled runs. Shorter runs alert sooner and cost more queries.')
@minValue(5)
@maxValue(60)
param frequencyMinutes int = 5

@description('Minutes after ingestion before a row is evaluated, so it is queryable when the run reads it.')
@minValue(1)
@maxValue(60)
param settleDelayMinutes int = 5

@description('Minutes of first-ingestion history re-checked for crossings that a missed or late run did not alert. Must be at least (alertVisibilityRuns + 1) x frequencyMinutes, or no retry slot exists; deployment fails otherwise.')
@minValue(15)
@maxValue(1440)
param catchUpMinutes int = 60

@description('Runs after which a rule run\'s alerts are queryable in SecurityAlert. A missed crossing is retried only every this many runs, so a retry never runs before the previous attempt\'s alert is visible. Raise it if SecurityAlert ingestion is slower than (alertVisibilityRuns - 1) x frequencyMinutes; too low a value can raise a second alert (grouping still keeps one incident).')
@minValue(2)
@maxValue(12)
param alertVisibilityRuns int = 2

@description('Scopes detection keys and rule names to this deployment. Use a distinct value for each deployment of this content in one workspace, so they never suppress each other\'s alerts. Lowercase letters, digits and hyphens.')
@minLength(1)
@maxLength(32)
param detectionKeyScope string = 'default'

@description('Minutes between runs of the beyond-tolerance monitor; each run evaluates exactly the first ingestions of the last interval.')
@minValue(60)
@maxValue(1440)
param toleranceFrequencyMinutes int = 60

@description('Longest delay between event time and first ingestion that the rules evaluate (outage SLO plus drain). Azure Monitor rewrites event times older than two days.')
@minValue(30)
@maxValue(2820)
param maxIngestionDelayMinutes int = 360

@description('Event-time bucket for threshold counting.')
@minValue(1)
@maxValue(60)
param bucketMinutes int = 10

@description('Distinct failed network logons from one address in one bucket that raise an alert.')
@minValue(2)
param bruteForceThreshold int = 10

@description('Distinct firewall denials from one address in one bucket that raise an alert.')
@minValue(2)
param firewallDenyThreshold int = 20

@description('Alerts for the same IP entity within this duration join one incident.')
param incidentGroupingLookback string = 'PT5H'

@description('Reopen a closed matching incident instead of creating a new one. Unavailable in the Defender portal.')
param reopenClosedIncidents bool = false

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

resource parser 'Microsoft.OperationalInsights/workspaces/savedSearches@2025-07-01' = {
  parent: workspace
  name: 'bower-security-events'
  properties: {
    category: 'Bower'
    displayName: 'BowerSecurityEvents: replay-collapsed Bower events'
    functionAlias: 'BowerSecurityEvents'
    query: loadTextContent('bower-security-events.kql')
    version: 2
  }
}

// Same collapse for chosen event types, without the large dynamic columns: the rules use it.
resource typedParser 'Microsoft.OperationalInsights/workspaces/savedSearches@2025-07-01' = {
  parent: workspace
  name: 'bower-security-events-of-type'
  properties: {
    category: 'Bower'
    displayName: 'BowerSecurityEventsOfType: replay-collapsed Bower events of given types'
    functionAlias: 'BowerSecurityEventsOfType'
    functionParameters: 'eventTypes:dynamic'
    query: loadTextContent('bower-security-events-of-type.kql')
    version: 2
  }
}

// Catch-up retries in slots alertVisibilityRuns, 2 x alertVisibilityRuns, ...: without room
// for the first one a missed crossing would never be retried.
var catchUpMinutesChecked = catchUpMinutes >= (alertVisibilityRuns + 1) * frequencyMinutes
  ? catchUpMinutes
  : fail('catchUpMinutes must be at least (alertVisibilityRuns + 1) x frequencyMinutes, or missed crossings are never retried.')

// TimeGenerated look-back: the oldest bucket a run evaluates, plus settle, catch-up and
// Sentinel's five-minute scheduling delay with five minutes of margin.
var queryPeriodMinutes = maxIngestionDelayMinutes + bucketMinutes + catchUpMinutesChecked + settleDelayMinutes + 10

// Each anchor is the rule file's default line; a unit test keeps them present.
func tune(query string, rule string, scope string, defaultThreshold int, threshold int, frequency int, settle int, catchUp int, maxDelay int, bucket int, spacing int) string =>
  replace(replace(replace(replace(replace(replace(replace(replace(query,
    'let ruleKey = "${rule}:default";', 'let ruleKey = "${rule}:${scope}";'),
    'let threshold = ${defaultThreshold};', 'let threshold = ${threshold};'),
    'let bucketSize = 10m;', 'let bucketSize = ${bucket}m;'),
    'let settleDelay = 5m;', 'let settleDelay = ${settle}m;'),
    'let frequency = 5m;', 'let frequency = ${frequency}m;'),
    'let catchUp = 60m;', 'let catchUp = ${catchUp}m;'),
    'let maxDelay = 360m;', 'let maxDelay = ${maxDelay}m;'),
    'let retrySpacing = 2;', 'let retrySpacing = ${spacing};')

var bruteForceQuery = tune(loadTextContent('rules/wec-brute-force.kql'), 'bower-wec-brute-force', detectionKeyScope, 10, bruteForceThreshold,
  frequencyMinutes, settleDelayMinutes, catchUpMinutesChecked, maxIngestionDelayMinutes, bucketMinutes, alertVisibilityRuns)
var firewallQuery = tune(loadTextContent('rules/firewall-deny.kql'), 'bower-firewall-deny', detectionKeyScope, 20, firewallDenyThreshold,
  frequencyMinutes, settleDelayMinutes, catchUpMinutesChecked, maxIngestionDelayMinutes, bucketMinutes, alertVisibilityRuns)
var toleranceQuery = replace(replace(replace(loadTextContent('rules/beyond-tolerance.kql'),
  'let maxDelay = 360m;', 'let maxDelay = ${maxIngestionDelayMinutes}m;'),
  'let settleDelay = 5m;', 'let settleDelay = ${settleDelayMinutes}m;'),
  'let frequency = 60m;', 'let frequency = ${toleranceFrequencyMinutes}m;')

// Rule display names must be unique per workspace.
var nameSuffix = detectionKeyScope == 'default' ? '' : ' [${detectionKeyScope}]'

var detectionDetails = {
  BowerDetectionKey: 'BowerDetectionKey'
  BucketStart: 'BucketStart'
  DistinctEvents: 'DistinctEvents'
  CrossedAt: 'CrossedAt'
  EvaluationPath: 'EvaluationPath'
  EvaluatedAt: 'EvaluatedAt'
  ReplayedRows: 'ReplayedRows'
  LateEvents: 'LateEvents'
  MaxDeliveryDelay: 'MaxDeliveryDelay'
}

var ipGrouping = {
  createIncident: true
  groupingConfiguration: {
    enabled: true
    reopenClosedIncident: reopenClosedIncidents
    lookbackDuration: incidentGroupingLookback
    matchingMethod: 'Selected'
    groupByEntities: ['IP']
    groupByAlertDetails: []
    groupByCustomDetails: []
  }
}

resource bruteForce 'Microsoft.SecurityInsights/alertRules@2025-09-01' = {
  scope: workspace
  name: guid(workspace.id, 'bower-wec-brute-force', detectionKeyScope)
  kind: 'Scheduled'
  properties: {
    displayName: 'Bower: Windows failed network logons from one address (replay-safe)${nameSuffix}'
    description: 'At least ${bruteForceThreshold} distinct Windows 4625 network logon failures from one source address in a ${bucketMinutes}-minute event-time bucket. Replayed Bower rows are collapsed by BowerSecurityEvents and late events are evaluated once, at first ingestion, up to ${maxIngestionDelayMinutes} minutes late.'
    enabled: enableRules
    severity: 'Medium'
    query: bruteForceQuery
    queryFrequency: 'PT${frequencyMinutes}M'
    queryPeriod: 'PT${queryPeriodMinutes}M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    // Suppression stops every evaluation for all entities, which would miss late events.
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: ['CredentialAccess']
    techniques: ['T1110']
    eventGroupingSettings: { aggregationKind: 'AlertPerResult' }
    entityMappings: [
      { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'SourceIpAddress' }] }
    ]
    customDetails: detectionDetails
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Bower: failed network logons from {{SourceIpAddress}}'
      alertDescriptionFormat: '{{DistinctEvents}} distinct failures in the bucket starting {{BucketStart}} (key {{BowerDetectionKey}}).'
    }
    incidentConfiguration: ipGrouping
  }
  dependsOn: [parser, typedParser]
}

resource firewallDeny 'Microsoft.SecurityInsights/alertRules@2025-09-01' = {
  scope: workspace
  name: guid(workspace.id, 'bower-firewall-deny', detectionKeyScope)
  kind: 'Scheduled'
  properties: {
    displayName: 'Bower: repeated firewall denials from one address (replay-safe)${nameSuffix}'
    description: 'At least ${firewallDenyThreshold} distinct firewall denials from one source address in a ${bucketMinutes}-minute event-time bucket. Replayed Bower rows are collapsed by BowerSecurityEvents and late events are evaluated once, at first ingestion, up to ${maxIngestionDelayMinutes} minutes late.'
    enabled: enableRules
    severity: 'Low'
    query: firewallQuery
    queryFrequency: 'PT${frequencyMinutes}M'
    queryPeriod: 'PT${queryPeriodMinutes}M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: ['Discovery']
    techniques: ['T1046']
    eventGroupingSettings: { aggregationKind: 'AlertPerResult' }
    entityMappings: [
      { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'SourceIpAddress' }] }
    ]
    customDetails: detectionDetails
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Bower: repeated firewall denials from {{SourceIpAddress}}'
      alertDescriptionFormat: '{{DistinctEvents}} distinct denials in the bucket starting {{BucketStart}} (key {{BowerDetectionKey}}).'
    }
    incidentConfiguration: ipGrouping
  }
  dependsOn: [parser, typedParser]
}

resource beyondTolerance 'Microsoft.SecurityInsights/alertRules@2025-09-01' = {
  scope: workspace
  name: guid(workspace.id, 'bower-beyond-tolerance', detectionKeyScope)
  kind: 'Scheduled'
  properties: {
    displayName: 'Bower: events arrived later than the replay-safe rules evaluate${nameSuffix}'
    description: 'Bower events first ingested more than ${maxIngestionDelayMinutes} minutes after their event time, or whose TimeGenerated Azure Monitor rewrote. The replay-safe rules did not evaluate them; investigate the outage and hunt manually.'
    enabled: enableRules
    severity: 'Informational'
    query: toleranceQuery
    queryFrequency: 'PT${toleranceFrequencyMinutes}M'
    // Candidates are bounded to two days in the query; the 14-day look-back (the maximum)
    // finds an earlier copy of a replay whose own TimeGenerated Azure rewrote.
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: []
    techniques: []
    eventGroupingSettings: { aggregationKind: 'AlertPerResult' }
    entityMappings: [
      { entityType: 'Host', fieldMappings: [{ identifier: 'HostName', columnName: 'CollectorId' }] }
    ]
    customDetails: {
      LateEvents: 'LateEvents'
      RewrittenTimes: 'RewrittenTimes'
      OldestEvent: 'OldestEvent'
      MaxDeliveryDelay: 'MaxDeliveryDelay'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT24H'
        matchingMethod: 'Selected'
        groupByEntities: ['Host']
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
  dependsOn: [parser, typedParser]
}

output parserFunction string = parser.properties.functionAlias
output ruleIds array = [bruteForce.id, firewallDeny.id, beyondTolerance.id]
output queryPeriod string = 'PT${queryPeriodMinutes}M'
