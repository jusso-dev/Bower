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

/** Recurring background job status. Metadata only: never payloads or error text. */
export interface BackgroundJob {
  id: string;
  schedule: string;
  lastRunAt: string | null;
  lastState: string | null;
  nextRunAt: string | null;
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
  jobs?: BackgroundJob[] | null;
  /** Policy bundle hash an administrator expects this collector to run. */
  desiredPolicyHash?: string | null;
  /** Null when no desired policy is set. */
  policyInSync?: boolean | null;
  /** Last witnessed queue ledger sequence (tamper evidence). */
  ledgerSequence?: number | null;
  deadLettered?: number;
  /** Approved privacy profile version an administrator assigned. Null when unassigned. */
  desiredPrivacyProfile?: DesiredPrivacyProfile | null;
  /** Privacy profile hash from the latest heartbeat: "sha256:<hex>" or "default". */
  reportedPrivacyProfileHash?: string | null;
  /** Null when no privacy profile version is assigned. */
  privacyProfileInSync?: boolean | null;
}

export interface DesiredPrivacyProfile {
  versionId: string;
  profileId: string;
  version: string;
  contentHash: string;
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
  policyDrift?: number;
  deadLettered?: number;
  /** Active collectors whose fresh heartbeat reports a hash other than the assigned version's. */
  privacyProfileDrift?: number;
  /** At most 12 rows; fewer than privacyProfileDrift when truncated. */
  privacyProfileExceptions?: PrivacyProfileDrift[] | null;
  /**
   * Part of sourcesDegraded without evidence: every source of a stale, pending, suspended
   * or revoked collector, and "pending" sources (not yet seen, in allowance) of active ones.
   * sourcesReporting + sourcesDegraded is every known source.
   */
  sourcesUnknown?: number;
}

/** Desired privacy profile assignment against the collector's observed hash. Metadata only. */
export interface PrivacyProfileDrift {
  collectorId: string;
  machineName: string;
  assignmentRevision: number;
  assignedAt: string;
  versionId: string;
  profileId: string;
  version: string;
  assignedHash: string;
  /** "sha256:<hex>", "default" or null when the collector did not report one. */
  observedHash: string | null;
  /** Time of the heartbeat that reported observedHash. */
  observedAt: string;
  /** True once a heartbeat at least two minutes after the assignment still differs. */
  mismatchConfirmed: boolean;
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
  /** Set when Bower acted for a person, for example a setup canary result. */
  initiatedByObjectId?: string | null;
  initiatedByName?: string | null;
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

export type PrivacyProfileVersionStatus = "PendingReview" | "Approved" | "Rejected";

export interface PrivacyProfileCustomDetectorSummary {
  id: string;
  description?: string | null;
  action: string;
}

export interface PrivacyProfileValidation {
  valid: boolean;
  errors: string[];
  profileId: string | null;
  version: string | null;
  contentHash: string | null;
  customDetectors: PrivacyProfileCustomDetectorSummary[];
  secretFieldNames: number;
  detectorOverrides: number;
  fieldRules: number;
}

export interface PrivacyProfileFinding {
  detectorId: string;
  action: string;
  path: string;
}

export interface PrivacyProfilePreview {
  valid: boolean;
  errors: string[];
  redacted: string | null;
  findings: PrivacyProfileFinding[];
}

export interface PrivacyProfileVersionSummary {
  id: string;
  profileId: string;
  version: string;
  description?: string | null;
  contentHash: string;
  changeSummary: string;
  status: PrivacyProfileVersionStatus;
  authorName?: string | null;
  createdAt: string;
  reviewerName?: string | null;
  reviewedAt?: string | null;
  reviewReason?: string | null;
  assignedCollectors: number;
}

export interface PrivacyProfileVersionDetail extends PrivacyProfileVersionSummary {
  content: string;
  authorObjectId: string;
  previousApprovedVersionId: string | null;
}

export interface PrivacyProfileAssignment {
  id: number;
  collectorId: string;
  versionId?: string | null;
  profileId?: string | null;
  version?: string | null;
  action: "assigned" | "cleared";
  reason: string;
  actorName?: string | null;
  occurredAt: string;
}

/** Plain-language progress state of a guided step. Rendered with text and icon, never colour alone. */
export type GuidedState = "complete" | "attention" | "blocked" | "in-progress" | "not-started";

/** One validation result. `fix` is set for every state except "pass". */
export interface GuidedCheck {
  id: string;
  state: "pass" | "warn" | "fail" | "pending";
  message: string;
  fix?: string | null;
}

export type SetupStepId =
  | "sign-in"
  | "entra"
  | "destination"
  | "collector"
  | "probe"
  | "canary"
  | "proof";

export interface SetupStep {
  id: SetupStepId;
  state: GuidedState;
  checks: GuidedCheck[];
  updatedBy: string | null;
  updatedAt: string | null;
}

export interface SetupDestination {
  workspaceId: string;
  workspaceResourceId: string | null;
  dcrResourceId: string | null;
  table: string;
  updatedBy: string;
  updatedAt: string;
}

export interface SetupProbeOption {
  profile: string;
  title: string;
  description: string;
  packId: string | null;
  expectedEventType: string | null;
}

/**
 * One onboarding canary run. `collectorAccepted` is collector acceptance only: delivery is
 * proven only when `mode` is "verified". "simulated" never counts as proof.
 */
export interface SetupCanaryRun {
  id: string;
  profile: string;
  state: "running" | "completed" | "interrupted";
  mode: "verified" | "failed" | "simulated" | null;
  outcome: string | null;
  message: string | null;
  fix: string | null;
  collectorAccepted: boolean;
  eventId: string | null;
  workspaceId: string;
  table: string;
  latencySeconds: number | null;
  hasSignature: boolean;
  hasBundle: boolean;
  requestedBy: string;
  requestedAt: string;
  completedAt: string | null;
}

export interface SetupStatus {
  canChange: boolean;
  steps: SetupStep[];
  destination: SetupDestination | null;
  probe: { profile: string; updatedBy: string; updatedAt: string } | null;
  probeOptions: SetupProbeOption[];
  canary: {
    configured: boolean;
    verifierConfigured: boolean;
    signingConfigured: boolean;
    collectorHost: string | null;
    timeoutMinutes: number;
  };
  latestRun: SetupCanaryRun | null;
}

export interface SetupCheckResult {
  checks: GuidedCheck[];
  checkedAt: string;
}
