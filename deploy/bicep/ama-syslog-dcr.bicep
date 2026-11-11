// Azure Monitor Agent collection of Bower events from local syslog on Linux
// (docs/getting-started/azure-monitor-agent.md). A collector with BOWER_OUTPUT=ama-syslog writes each
// policy-approved, redacted envelope to /dev/log as "bower: bower-b64:<base64 JSON>" on local4.
// This rule collects that facility, decodes the envelope and maps it into BowerSecurity_CL with
// the same columns as main.bicep's Logs Ingestion rule (tests derive one from the other).
// Other local4 messages match no row here and are not stored. A "bower" message that does not
// decode goes to the Syslog table instead (keepUndecodedInSyslog, #231). Plan-only until deployed.
//
// The transform is generated from SentinelSchema.Default (Bower.Dcr SyslogTransformKql);
// CloudAgentQuickStartTests renders it and fails, naming this file, when it differs.
// It keeps only messages tagged "bower" (ProcessName) whose whole text, apart from surrounding
// white space, is the marker and one base64 value. Any local account can still send such a
// message (docs/deployment/ama-syslog-output.md, trust boundary). schemaVersion is pinned to 1.0.0,
// as in main.bicep: when the envelope version changes, deploy the new rule first, then
// upgrade collectors. Deployed and run with Azure Monitor Agent 1.45.1 on 10-11-2026 (#249),
// including Origin = the agent's Computer, which a forged message cannot change (#228).
targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace name, already holding BowerSecurity_CL from main.bicep.')
param workspaceName string

@description('Resource group of the workspace. Defaults to the deployment\'s resource group.')
param workspaceResourceGroup string = resourceGroup().name

// Bicep cannot default this to the existing workspace's region: a resource's location must be
// known when the deployment starts (BCP120). Pass the workspace's region when it differs.
@description('Region for the rule. Must be the workspace\'s region.')
param location string = resourceGroup().location

@description('Tags for the rule.')
param tags object = {}

@description('Bower resource name prefix.')
@minLength(3)
@maxLength(40)
param namePrefix string = 'bower'

@description('Syslog facility Bower writes to (BOWER_AMA_SYSLOG_FACILITY 20 is local4).')
@allowed(['local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'])
param facility string = 'local4'

@description('Optional data collection endpoint resource ID, for example when the agent reaches Azure Monitor over Private Link.')
param dataCollectionEndpointId string = ''

@description('Store a bower message the transform cannot decode (cut short, padded, other schemaVersion) in the Syslog table, as it arrived, instead of dropping it.')
param keepUndecodedInSyslog bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
  scope: resourceGroup(workspaceResourceGroup)
}

resource rule 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: '${namePrefix}-ama-syslog-dcr'
  location: location
  tags: tags
  kind: 'Linux'
  properties: {
    description: 'Bower security events from local syslog, collected by Azure Monitor Agent'
    dataCollectionEndpointId: empty(dataCollectionEndpointId) ? null : dataCollectionEndpointId
    dataSources: {
      syslog: [
        {
          name: 'bowerSyslog'
          streams: ['Microsoft-Syslog']
          facilityNames: [facility]
          logLevels: ['Notice', 'Warning', 'Error', 'Critical', 'Alert', 'Emergency']
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
    dataFlows: concat([
      {
        streams: ['Microsoft-Syslog']
        destinations: ['BowerWorkspace']
        outputStream: 'Custom-BowerSecurity_CL'
        transformKql: '''
          source
          | where ProcessName == "bower"
          | extend b64 = extract(@"^\s*bower-b64:([A-Za-z0-9+/]+={0,2})\s*$", 1, SyslogMessage)
          | where isnotempty(b64)
          | extend e = parse_json(base64_decodestring(b64))
          | where tostring(e.schemaVersion) == "1.0.0"
          | project
              TimeGenerated = todatetime(e.timeGenerated),
              EventId = substring(tostring(e.eventId), 0, 128),
              EventOriginalId = substring(tostring(e.eventOriginalId), 0, 256),
              EventCategory = substring(tostring(e.eventCategory), 0, 128),
              EventType = substring(tostring(e.eventType), 0, 128),
              EventAction = substring(tostring(e.eventAction), 0, 128),
              EventResult = substring(tostring(e.eventResult), 0, 32),
              EventSeverity = substring(tostring(e.eventSeverity), 0, 32),
              ApplicationName = substring(tostring(e.application.name), 0, 128),
              ApplicationEnvironment = substring(tostring(e.application.environment), 0, 64),
              ActorUserId = substring(tostring(e.actor.userId), 0, 256),
              ActorUsername = substring(tostring(e.actor.username), 0, 256),
              SourceIpAddress = substring(tostring(e.source.ipAddress), 0, 64),
              CorrelationId = substring(tostring(e.request.correlationId), 0, 256),
              PolicyId = substring(tostring(e.security.policyId), 0, 128),
              PolicyVersion = substring(tostring(e.security.policyVersion), 0, 32),
              PolicyHash = substring(tostring(e.security.policyHash), 0, 128),
              ValueScore = toint(e.security.valueScore),
              CollectorId = substring(tostring(e.collector.id), 0, 128),
              PrivacyDetected = e.privacy.detected,
              Labels = e.labels,
              RawEnvelope = e,
              TimeObserved = todatetime(e.timeObserved),
              EventOutcomeReason = substring(tostring(e.eventOutcomeReason), 0, 1024),
              Target = e.target,
              Change = e.change,
              Attributes = e.attributes,
              Origin = pack("kind", "ama-syslog", "host", Computer)
        '''
      }
    ], keepUndecodedInSyslog ? [
      {
        streams: ['Microsoft-Syslog']
        destinations: ['BowerWorkspace']
        outputStream: 'Microsoft-Syslog'
        transformKql: '''
          source
          | where ProcessName == "bower"
          | extend b64 = extract(@"^\s*bower-b64:([A-Za-z0-9+/]+={0,2})\s*$", 1, SyslogMessage)
          | extend v = tostring(parse_json(base64_decodestring(b64)).schemaVersion)
          | where isempty(b64) or v != "1.0.0"
          | project-away b64, v
        '''
      }
    ] : [])
  }
}

output dataCollectionRuleId string = rule.id
