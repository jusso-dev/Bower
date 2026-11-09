// Starter analytics for the owasp-asvs-app-logging pack (docs/security/asvs-logging-pack.md).
// Reads BowerSecurity_CL through the BowerSecurityEvents functions deployed by main.bicep;
// deploy main.bicep first. Changes no table, DCR or stream schema. Rules are created disabled.
targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace with Microsoft Sentinel, BowerSecurity_CL and the main.bicep functions.')
param workspaceName string

@description('Create the rules enabled. Keep false until they are validated against this workspace.')
param enableRules bool = false

@description('Scopes detection keys and rule names to this deployment. Lowercase letters, digits and hyphens.')
@minLength(1)
@maxLength(32)
param detectionKeyScope string = 'default'

@description('IANA time zone for business hours in the after-hours rule.')
param timeZone string = 'Australia/Sydney'

@description('First business hour (local, 0-23).')
@minValue(0)
@maxValue(23)
param businessStartHour int = 7

@description('Hour business ends (local, 1-24, exclusive).')
@minValue(1)
@maxValue(24)
param businessEndHour int = 19

@description('Distinct accounts with failed sign-ins from one address in one bucket that raise a spraying alert.')
@minValue(2)
param sprayAccountThreshold int = 10

@description('Records exported or read by one user in one hour that raise a mass export alert.')
@minValue(1)
param exportRecordThreshold int = 10000

@description('Exports by one user in one hour that raise a mass export alert.')
@minValue(1)
param exportCountThreshold int = 5

@description('Minutes without events after which an application with recent history counts as silent.')
@minValue(15)
@maxValue(1440)
param silenceMinutes int = 60

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

var nameSuffix = detectionKeyScope == 'default' ? '' : ' [${detectionKeyScope}]'

// Each anchor is the rule file's default line; AsvsAnalyticsContentTests keeps them present.
func scoped(query string, rule string, scope string) string =>
  replace(query, 'let ruleKey = "${rule}:default";', 'let ruleKey = "${rule}:${scope}";')

var sprayQuery = replace(scoped(loadTextContent('rules/asvs/password-spray.kql'), 'bower-asvs-password-spray', detectionKeyScope),
  'let accountThreshold = 10;', 'let accountThreshold = ${sprayAccountThreshold};')
var privilegeQuery = scoped(loadTextContent('rules/asvs/privilege-change.kql'), 'bower-asvs-privilege-change', detectionKeyScope)
var afterHoursQuery = replace(replace(replace(
  scoped(loadTextContent('rules/asvs/admin-after-hours.kql'), 'bower-asvs-admin-after-hours', detectionKeyScope),
  'let timeZone = "Australia/Sydney";', 'let timeZone = "${timeZone}";'),
  'let businessStart = 7;', 'let businessStart = ${businessStartHour};'),
  'let businessEnd = 19;', 'let businessEnd = ${businessEndHour};')
var exportQuery = replace(replace(
  scoped(loadTextContent('rules/asvs/mass-export.kql'), 'bower-asvs-mass-export', detectionKeyScope),
  'let recordThreshold = 10000;', 'let recordThreshold = ${exportRecordThreshold};'),
  'let exportThreshold = 5;', 'let exportThreshold = ${exportCountThreshold};')
var silenceQuery = replace(scoped(loadTextContent('rules/asvs/log-silence.kql'), 'bower-asvs-log-silence', detectionKeyScope),
  'let silence = 60m;', 'let silence = ${silenceMinutes}m;')

// Look-back: maxDelay (360m) + bucket (60m at most) + catchUp (60m) + settle + frequency + margin.
var queryPeriod = 'PT500M'

var rules = [
  {
    key: 'bower-asvs-password-spray'
    displayName: 'Bower ASVS: password spraying or credential stuffing from one address'
    description: 'At least ${sprayAccountThreshold} distinct accounts failed application sign-in from one source address in a 10-minute bucket. SuccessesAfterFailures shows sign-ins that worked from the same address.'
    severity: 'Medium'
    query: sprayQuery
    period: queryPeriod
    tactics: ['CredentialAccess']
    techniques: ['T1110']
    entity: { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'SourceIpAddress' }] }
  }
  {
    key: 'bower-asvs-privilege-change'
    displayName: 'Bower ASVS: privilege, role or permission change'
    description: 'A role membership, permission or privileged grant changed in an application.'
    severity: 'Low'
    query: privilegeQuery
    period: queryPeriod
    tactics: ['PrivilegeEscalation', 'Persistence']
    techniques: ['T1098']
    entity: { entityType: 'Account', fieldMappings: [{ identifier: 'Name', columnName: 'ActorUserId' }] }
  }
  {
    key: 'bower-asvs-admin-after-hours'
    displayName: 'Bower ASVS: administrative action outside business hours'
    description: 'A privileged or configuration action outside ${businessStartHour}:00-${businessEndHour}:00 on a weekday, or on a weekend, in ${timeZone}.'
    severity: 'Medium'
    query: afterHoursQuery
    period: queryPeriod
    tactics: ['Persistence', 'DefenseEvasion']
    techniques: ['T1078']
    entity: { entityType: 'Account', fieldMappings: [{ identifier: 'Name', columnName: 'ActorUserId' }] }
  }
  {
    key: 'bower-asvs-mass-export'
    displayName: 'Bower ASVS: mass export or bulk sensitive reads by one user'
    description: 'One user exported or read at least ${exportRecordThreshold} sensitive records, or ran at least ${exportCountThreshold} exports, in one hour.'
    severity: 'High'
    query: exportQuery
    period: queryPeriod
    tactics: ['Exfiltration', 'Collection']
    techniques: ['T1567', 'T1530']
    entity: { entityType: 'Account', fieldMappings: [{ identifier: 'Name', columnName: 'ActorUserId' }] }
  }
  {
    key: 'bower-asvs-log-silence'
    displayName: 'Bower ASVS: application stopped sending security events'
    description: 'An application that sent security events in the last 7 days has sent none for ${silenceMinutes} minutes.'
    severity: 'Medium'
    query: silenceQuery
    period: 'P7D'
    tactics: ['DefenseEvasion']
    techniques: ['T1562']
    entity: { entityType: 'CloudApplication', fieldMappings: [{ identifier: 'Name', columnName: 'ApplicationName' }] }
  }
]

resource alertRules 'Microsoft.SecurityInsights/alertRules@2025-09-01' = [for rule in rules: {
  scope: workspace
  name: guid(workspace.id, rule.key, detectionKeyScope)
  kind: 'Scheduled'
  properties: {
    displayName: '${rule.displayName}${nameSuffix}'
    description: rule.description
    enabled: enableRules
    severity: rule.severity
    query: rule.query
    queryFrequency: rule.key == 'bower-asvs-log-silence' ? 'PT15M' : 'PT5M'
    queryPeriod: rule.period
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: rule.tactics
    techniques: rule.techniques
    eventGroupingSettings: { aggregationKind: 'AlertPerResult' }
    entityMappings: [rule.entity]
    customDetails: { BowerDetectionKey: 'BowerDetectionKey' }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}]

output ruleIds array = [for (rule, i) in rules: alertRules[i].id]
