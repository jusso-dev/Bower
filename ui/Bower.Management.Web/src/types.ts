export type CollectorStatus =
  | "Pending"
  | "Approved"
  | "Active"
  | "Suspended"
  | "Revoked";

export interface SourceReport {
  id: string;
  type: string;
  status: string;
  lagSeconds: number | null;
  lastEventAt: string | null;
}

export interface OutputReport {
  id: string;
  type: string;
  status: string;
  lastAcknowledgedAt: string | null;
  lastErrorCode: string | null;
}

export interface Collector {
  id: string;
  machineName: string;
  environment: string;
  version: string;
  status: CollectorStatus;
  principalObjectId: string;
  firstSeenAt: string;
  lastSeenAt: string;
  configurationHash: string;
  policyHash: string;
  queueDepth: number;
  deliveryStatus: string;
  sources: SourceReport[];
  outputs: OutputReport[];
}

export interface Overview {
  totalCollectors: number;
  pendingApproval: number;
  unhealthyCollectors: number;
  staleCollectors: number;
  totalQueueDepth: number;
  sourcesReporting: number;
  sourcesDegraded: number;
  exceptions: Collector[];
}

export interface Approval {
  id: string;
  collectorId: string;
  action: string;
  reason: string;
  actorObjectId: string;
  actorName: string;
  occurredAt: string;
}

export interface Audit {
  id: string;
  action: string;
  targetType: string;
  targetId: string;
  actorObjectId: string;
  actorName: string;
  occurredAt: string;
}

export interface Access {
  objectId: string;
  displayName: string;
  roles: string[];
  developmentAuthentication: boolean;
}

export interface PipelineNode {
  id: string;
  kind: string;
  type: string;
}

export interface PipelineEdge {
  from: string;
  to: string;
}

export interface PipelineTemplate {
  id: string;
  name: string;
  version: string;
  description: string;
  nodes: PipelineNode[];
  edges: PipelineEdge[];
  tags?: string[];
}

export type CustomLogFormat = "Json" | "Csv" | "KeyValue" | "Regex";
export type CustomLogValueType =
  | "Text"
  | "DateTime"
  | "IpAddress"
  | "WholeNumber"
  | "Boolean";

export interface CustomLogField {
  sourceName: string;
  type: CustomLogValueType;
  ocsfPath: string | null;
  asimField: string | null;
  sensitive: boolean;
}

export interface CustomLogParserConfiguration {
  version: string;
  format: CustomLogFormat;
  fields: CustomLogField[];
  delimiter: string | null;
  keyValueSeparator: string | null;
  pattern: string | null;
}

export interface CustomLogSchemaField {
  name: string;
  type: CustomLogValueType;
  required: boolean;
  ocsfPath: string | null;
  asimField: string | null;
}

export interface CustomLogParserTest {
  name: string;
  sourceLine: number | null;
  shouldParse: boolean;
  expectedFields: string[];
  expectedOcsfMappings: string[];
  expectedAsimMappings: string[];
}

export interface CustomLogPreviewValue {
  type: CustomLogValueType;
  value: string;
  ocsfPath: string | null;
  asimField: string | null;
  redacted: boolean;
}

export interface CustomLogPreviewRow {
  sourceLine: number;
  fields: Record<string, CustomLogPreviewValue>;
}

export interface CustomLogPreview {
  isValid: boolean;
  parsedLineCount: number;
  rejectedLineCount: number;
  issues: string[];
  rows: CustomLogPreviewRow[];
}

export interface CustomLogGeneration {
  format: CustomLogFormat;
  confidence: number;
  rationale: string[];
  configuration: CustomLogParserConfiguration;
  schema: {
    version: string;
    fields: CustomLogSchemaField[];
  };
  tests: CustomLogParserTest[];
  preview: CustomLogPreview;
}
