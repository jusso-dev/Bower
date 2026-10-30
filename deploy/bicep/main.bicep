// Generated shape must match Bower.Dcr SentinelSchema.Default (enforced by tests).
// Regenerate an equivalent ARM template with: bower dcr generate
targetScope = 'resourceGroup'

@description('Region matching the Log Analytics workspace.')
param location string = resourceGroup().location

@description('Existing Log Analytics workspace name.')
param workspaceName string

@description('Bower resource name prefix.')
@minLength(3)
@maxLength(40)
param namePrefix string = 'bower'

@description('Existing Entra service-principal object ID for ingestion. Never a client secret or application client ID. Leave empty when creating a managed identity.')
param ingestPrincipalObjectId string = ''

@description('Create a user-assigned managed identity and grant it write access on this DCR only. Plan-only until explicitly deployed.')
param createIngestIdentity bool = false

@description('Optional exact OIDC issuer for a new identity federation. Use the reviewed plan generator; no wildcards.')
param federationIssuer string = ''

@description('Optional exact OIDC subject, for example system:serviceaccount:namespace:collector.')
param federationSubject string = ''

resource ingestIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (createIngestIdentity) {
  name: '${namePrefix}-ingest'
  location: location
}

resource ingestFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = if (createIngestIdentity && !empty(federationIssuer) && !empty(federationSubject)) {
  parent: ingestIdentity
  name: 'bower-ingestion'
  properties: {
    issuer: federationIssuer
    subject: federationSubject
    audiences: ['api://AzureADTokenExchange']
  }
}

var selectedIngestPrincipal = createIngestIdentity ? ingestIdentity!.properties.principalId : ingestPrincipalObjectId
var metricsPublisherRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')

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
    retentionInDays: 90
    // Total retention includes archive; this does not prove interactive searchability.
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
        { name: 'PrivacyDetected', type: 'dynamic' }
        { name: 'Labels', type: 'dynamic' }
        { name: 'RawEnvelope', type: 'dynamic' }
        { name: 'TimeObserved', type: 'dateTime' }
        { name: 'EventOutcomeReason', type: 'string' }
        { name: 'Target', type: 'dynamic' }
        { name: 'Change', type: 'dynamic' }
        { name: 'Attributes', type: 'dynamic' }
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

resource rule 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
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
  dependsOn: [table]
}

resource ingestionGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (createIngestIdentity || !empty(ingestPrincipalObjectId)) {
  name: guid(rule.id, createIngestIdentity ? ingestIdentity!.id : ingestPrincipalObjectId, metricsPublisherRole)
  scope: rule
  properties: {
    roleDefinitionId: metricsPublisherRole
    principalId: selectedIngestPrincipal
    principalType: 'ServicePrincipal'
  }
}

// Optional Private Link for relays and collectors in a private network (docs/deployment/relay.md).
// Empty privateLinkScopeName (the default) deploys nothing here. The private DNS zones for the
// endpoint stay with the network owner (docs/operations/doctor-and-dcr.md#private-link-and-expressroute).
@description('Optional new Azure Monitor Private Link Scope. When set, the DCE and workspace join it so the Logs Ingestion API is reachable over Private Link. Empty changes nothing.')
param privateLinkScopeName string = ''

@description('Ingestion access mode of the new scope. PrivateOnly: networks linked to the scope can ingest only into resources in it.')
@allowed([
  'PrivateOnly'
  'Open'
])
param privateLinkIngestionAccessMode string = 'PrivateOnly'

@description('Optional subnet resource ID for the scope\'s private endpoint, in the network where the relay runs. Empty creates the scope without an endpoint.')
param privateEndpointSubnetId string = ''

resource privateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-07-01-preview' = if (!empty(privateLinkScopeName)) {
  name: empty(privateLinkScopeName) ? 'unused' : privateLinkScopeName
  location: 'global'
  properties: {
    accessModeSettings: {
      ingestionAccessMode: privateLinkIngestionAccessMode
      queryAccessMode: 'Open'
    }
  }
}

resource scopedEndpoint 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = if (!empty(privateLinkScopeName)) {
  parent: privateLinkScope
  name: '${namePrefix}-dce'
  properties: {
    linkedResourceId: endpoint.id
  }
}

resource scopedWorkspace 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = if (!empty(privateLinkScopeName)) {
  parent: privateLinkScope
  name: workspaceName
  properties: {
    linkedResourceId: workspace.id
  }
}

// The endpoint belongs to the network's subscription/resource group, independently
// of the Sentinel resources. Its region is read from the existing virtual network.
var privateEndpointSubnetParts = split(privateEndpointSubnetId, '/')
resource privateEndpointNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' existing = if (!empty(privateEndpointSubnetId)) {
  name: empty(privateEndpointSubnetId) ? 'unused' : privateEndpointSubnetParts[8]
  scope: resourceGroup(
    empty(privateEndpointSubnetId) ? subscription().subscriptionId : privateEndpointSubnetParts[2],
    empty(privateEndpointSubnetId) ? resourceGroup().name : privateEndpointSubnetParts[4]
  )
}

module privateEndpoint './private-endpoint.bicep' = if (!empty(privateLinkScopeName) && !empty(privateEndpointSubnetId)) {
  name: '${namePrefix}-ampls-pe'
  scope: resourceGroup(
    empty(privateEndpointSubnetId) ? subscription().subscriptionId : privateEndpointSubnetParts[2],
    empty(privateEndpointSubnetId) ? resourceGroup().name : privateEndpointSubnetParts[4]
  )
  params: {
    name: '${namePrefix}-ampls-pe'
    connectionName: '${namePrefix}-ampls'
    subnetId: privateEndpointSubnetId
    location: !empty(privateLinkScopeName) && !empty(privateEndpointSubnetId) ? privateEndpointNetwork!.location : location
    privateLinkScopeId: privateLinkScope.id
  }
  dependsOn: [scopedEndpoint, scopedWorkspace]
}

output ingestManagedIdentityClientId string = createIngestIdentity ? ingestIdentity!.properties.clientId : ''
output ingestPrincipalId string = selectedIngestPrincipal
output dataCollectionEndpoint string = endpoint.properties.logsIngestion.endpoint
output dataCollectionRuleImmutableId string = rule.properties.immutableId
output streamName string = 'Custom-BowerSecurity'
output tableName string = table.name
output privateLinkScopeId string = empty(privateLinkScopeName) ? '' : privateLinkScope.id
output privateEndpointId string = !empty(privateLinkScopeName) && !empty(privateEndpointSubnetId) ? privateEndpoint!.outputs.privateEndpointId : ''
