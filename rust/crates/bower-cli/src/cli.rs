//! Command surface of the C# `bower` CLI (`src/Bower.Cli/Program.cs`).
//!
//! Every option the C# code reads is declared here, including ones its help text
//! omits (`--plan`, `--credential`, `--client-id`, `--timeout-minutes`, `--max`).
//! Clap only renders `--help` from these types; `args::parse` fills them with C#
//! `CliOptions` semantics, and commands validate required values so missing ones
//! produce the C# messages and exit code 1.

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "bower",
    about = "Bower security telemetry",
    disable_help_subcommand = true,
    disable_version_flag = true,
    subcommand_required = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the CLI version.
    Version,
    /// Load a policy directory strictly and print policy ids, versions and hashes.
    Validate(ValidateArgs),
    /// Validate pipeline files and print pipeline templates.
    #[command(subcommand)]
    Pipeline(PipelineCommand),
    /// Inspect, verify and replay the local SQLite queue (metadata only).
    #[command(subcommand)]
    Queue(QueueCommand),
    /// Send synthetic test events.
    #[command(subcommand)]
    Test(TestCommand),
    /// Generate collector ingest tokens.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Check a Bower deployment for silent-loss risks and misconfiguration (exit 1 on any FAIL).
    Doctor(DoctorArgs),
    /// Generate the Sentinel DCR template or diff a deployed DCR against Bower's schema.
    #[command(subcommand)]
    Dcr(DcrCommand),
    /// Generate ECDSA P-256 signing keys.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// Build, verify, inspect, test and diff signed content packs.
    #[command(subcommand)]
    Pack(PackCommand),
    /// Produce and verify signed Sentinel delivery evidence bundles.
    #[command(subcommand)]
    Evidence(EvidenceCommand),
    /// Developer project scaffolding.
    #[command(subcommand)]
    Developer(DeveloperCommand),
    /// Validate privacy profiles (custom detectors, secret field names) and preview redaction.
    #[command(subcommand)]
    Privacy(PrivacyCommand),
    /// Test sample events against policies offline (redaction, validation, selection).
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Create, verify and replay the verifiable long-term queue archive.
    #[command(subcommand)]
    Archive(ArchiveCommand),
    /// Check expected sources for silence from the activity the collector persisted.
    #[command(subcommand)]
    Sources(SourcesCommand),
    /// Stream post-redaction outcomes from a collector as JSON lines (bounded, audited).
    Tap(TapArgs),
    /// Live per-stage throughput, queue, delivery, syslog and tap counters from /v1/status.
    Top(TopArgs),
}

#[derive(Debug, Args)]
pub struct TapArgs {
    /// Collector base URL [default: http://127.0.0.1:4319] (alias --collector-url).
    #[arg(long = "collector", value_name = "URL")]
    pub collector: Option<String>,
    /// Tap point: redacted (every outcome), decided or queued. There is no pre-redaction point.
    #[arg(long = "stage", value_name = "redacted|decided|queued")]
    pub stage: Option<String>,
    /// Only events from this application.
    #[arg(long = "source", value_name = "APP")]
    pub source: Option<String>,
    /// Only events of this type.
    #[arg(long = "event-type", value_name = "TYPE")]
    pub event_type: Option<String>,
    /// Most frames [default: 100, capped by BOWER_TAP_MAX_EVENTS].
    #[arg(long = "limit", value_name = "N")]
    pub limit: Option<String>,
    /// Session length [default: 60, capped by BOWER_TAP_MAX_DURATION_SECONDS].
    #[arg(long = "duration", value_name = "SECONDS")]
    pub duration: Option<String>,
    /// Keep 1 in N matching outcomes [default: 1].
    #[arg(long = "sample", value_name = "N")]
    pub sample: Option<String>,
}

#[derive(Debug, Args)]
pub struct TopArgs {
    /// Collector base URL [default: http://127.0.0.1:4319] (alias --collector-url).
    #[arg(long = "collector", value_name = "URL")]
    pub collector: Option<String>,
    /// Seconds between samples, 1 to 60 [default: 2].
    #[arg(long = "interval", value_name = "SECONDS")]
    pub interval: Option<String>,
    /// Print one view (two samples an interval apart) and exit.
    #[arg(long = "once")]
    pub once: bool,
    /// Stop after N views.
    #[arg(long = "iterations", value_name = "N")]
    pub iterations: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Run sample events through the collector's intake offline and print each decision
    /// (metadata only; exit 3 when --expect does not match).
    Test(PolicyTestArgs),
    /// Population diff: run sample events through two policy directories (or, with any
    /// --baseline-*/--candidate-* bundle option or --at, two full trusted bundles at one
    /// fixed time) and list each event whose outcome changes (exit 3 with --fail-on-change).
    Diff(PolicyDiffArgs),
}

#[derive(Debug, Args)]
pub struct PolicyDiffArgs {
    /// Event JSON files (each evaluated as its own /v1/events request).
    #[arg(value_name = "EVENT.json")]
    pub files: Vec<String>,
    /// Current policy directory.
    #[arg(long = "baseline", value_name = "DIR")]
    pub baseline: Option<String>,
    /// Proposed policy directory.
    #[arg(long = "candidate", value_name = "DIR")]
    pub candidate: Option<String>,
    /// Exit 3 when any event's decision or deciding policy changes (bundle comparison:
    /// any reported field).
    #[arg(long = "fail-on-change")]
    pub fail_on_change: bool,
    /// Bundle comparison: signed baseline pack (repeatable).
    #[arg(long = "baseline-pack", value_name = "FILE")]
    pub baseline_packs: Vec<String>,
    /// Bundle comparison: PEM public key trusted to sign baseline packs (repeatable).
    #[arg(long = "baseline-trusted-key", value_name = "PUB")]
    pub baseline_trusted_keys: Vec<String>,
    /// Bundle comparison: baseline privacy profile.
    #[arg(long = "baseline-privacy-profile", value_name = "FILE")]
    pub baseline_privacy_profile: Option<String>,
    /// Bundle comparison: baseline privacy HMAC key file.
    #[arg(long = "baseline-hmac-key-file", value_name = "FILE")]
    pub baseline_hmac_key_file: Option<String>,
    /// Bundle comparison: baseline privacy HMAC key id [default: k1].
    #[arg(long = "baseline-hmac-key-id", value_name = "ID")]
    pub baseline_hmac_key_id: Option<String>,
    /// Bundle comparison: signed candidate pack (repeatable).
    #[arg(long = "candidate-pack", value_name = "FILE")]
    pub candidate_packs: Vec<String>,
    /// Bundle comparison: PEM public key trusted to sign candidate packs (repeatable).
    #[arg(long = "candidate-trusted-key", value_name = "PUB")]
    pub candidate_trusted_keys: Vec<String>,
    /// Bundle comparison: candidate privacy profile.
    #[arg(long = "candidate-privacy-profile", value_name = "FILE")]
    pub candidate_privacy_profile: Option<String>,
    /// Bundle comparison: candidate privacy HMAC key file.
    #[arg(long = "candidate-hmac-key-file", value_name = "FILE")]
    pub candidate_hmac_key_file: Option<String>,
    /// Bundle comparison: candidate privacy HMAC key id [default: k1].
    #[arg(long = "candidate-hmac-key-id", value_name = "ID")]
    pub candidate_hmac_key_id: Option<String>,
    /// Bundle comparison: evaluate every sample at this ISO 8601 time [default: now].
    #[arg(long = "at", value_name = "ISO")]
    pub at: Option<String>,
    /// `--at` was given (with or without a value).
    #[arg(skip)]
    pub at_given: bool,
    /// Any bundle option (or `--at`) was given: compare full bundles.
    #[arg(skip)]
    pub bundle: bool,
}

#[derive(Debug, Subcommand)]
pub enum ArchiveCommand {
    /// Copy every stored event not yet archived into new verifiable segments.
    Create(ArchiveCreateArgs),
    /// Recompute the archived ledger chain and segment digests (exit 3 when broken).
    Verify(ArchiveVerifyArgs),
    /// Verify the archive, then post selected events through a collector's full intake.
    Replay(ArchiveReplayArgs),
}

#[derive(Debug, Args)]
pub struct ArchiveCreateArgs {
    /// Archive directory.
    #[arg(long = "archive", value_name = "DIR")]
    pub archive: Option<String>,
    #[command(flatten)]
    pub database: DatabaseArgs,
    /// Collector id recorded in manifests [default: machine name].
    #[arg(long = "collector-id", value_name = "ID")]
    pub collector_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct ArchiveVerifyArgs {
    /// Archive directory.
    #[arg(long = "archive", value_name = "DIR")]
    pub archive: Option<String>,
    /// Ledger head witnessed elsewhere that the archived chain must pass through.
    #[arg(long = "anchor", value_name = "SEQUENCE:HASH")]
    pub anchor: Option<String>,
}

#[derive(Debug, Args)]
pub struct ArchiveReplayArgs {
    /// Archive directory.
    #[arg(long = "archive", value_name = "DIR")]
    pub archive: Option<String>,
    /// Collector base URL (sends BOWER_INGEST_TOKEN when set).
    #[arg(long = "collector-url", value_name = "URL")]
    pub collector_url: Option<String>,
    /// Earliest timeGenerated to replay (inclusive).
    #[arg(long = "from", value_name = "ISO")]
    pub from: Option<String>,
    /// Latest timeGenerated to replay (exclusive).
    #[arg(long = "to", value_name = "ISO")]
    pub to: Option<String>,
    /// Event type to replay (repeatable).
    #[arg(long = "event-type", value_name = "TYPE")]
    pub event_types: Vec<String>,
    /// Count the selection without sending.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum SourcesCommand {
    /// Offline silence check (exit 3 when any expected source is quiet).
    Check(SourcesCheckArgs),
}

#[derive(Debug, Args)]
pub struct SourcesCheckArgs {
    /// Source expectations JSON file.
    #[arg(long = "expectations", value_name = "FILE")]
    pub expectations: Option<String>,
    #[command(flatten)]
    pub database: DatabaseArgs,
}

#[derive(Debug, Args)]
pub struct PolicyTestArgs {
    /// Event JSON files (each evaluated as its own /v1/events request).
    #[arg(value_name = "EVENT.json")]
    pub files: Vec<String>,
    /// Policy directory [default: ./policies/default].
    #[arg(long = "policy-directory", value_name = "DIR")]
    pub policy_directory: Option<String>,
    /// Signed content pack (repeatable).
    #[arg(long = "pack", value_name = "FILE")]
    pub packs: Vec<String>,
    /// Public key trusted to sign packs (repeatable).
    #[arg(long = "trusted-key", value_name = "PUB")]
    pub trusted_keys: Vec<String>,
    /// Privacy profile YAML.
    #[arg(long = "privacy-profile", value_name = "FILE")]
    pub privacy_profile: Option<String>,
    /// Privacy HMAC key file.
    #[arg(long = "hmac-key-file", value_name = "FILE")]
    pub hmac_key_file: Option<String>,
    /// Privacy HMAC key id [default: k1].
    #[arg(long = "hmac-key-id", value_name = "ID")]
    pub hmac_key_id: Option<String>,
    /// Expected decision for every event (accept, redact-and-accept, reject, quarantine, ...).
    #[arg(long = "expect", value_name = "DECISION")]
    pub expect: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PrivacyCommand {
    /// Load a privacy profile strictly, run its custom detector tests and print metadata
    /// (exit 2 when the sample cannot be redacted).
    Validate(PrivacyValidateArgs),
}

#[derive(Debug, Args)]
pub struct PrivacyValidateArgs {
    /// Privacy profile YAML file.
    #[arg(value_name = "FILE")]
    pub file: Option<String>,
    /// HMAC key file (base64 or at least 32 raw bytes) [default: a random key].
    #[arg(long = "hmac-key-file", value_name = "FILE")]
    pub hmac_key_file: Option<String>,
    /// JSON event to redact with the profile; prints the redacted result.
    #[arg(long = "sample", value_name = "FILE")]
    pub sample: Option<String>,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Policy directory [default: ./policies/default].
    #[arg(long = "policy-directory", value_name = "PATH")]
    pub policy_directory: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PipelineCommand {
    /// Validate a pipeline YAML file (exit 2 when invalid).
    Validate(PipelineValidateArgs),
    /// Print a pipeline template as YAML.
    Template(PipelineTemplateArgs),
}

#[derive(Debug, Args)]
pub struct PipelineValidateArgs {
    /// Pipeline YAML file.
    #[arg(long = "file", value_name = "PATH")]
    pub file: Option<String>,
    /// Pipeline YAML file (when --file is not given).
    #[arg(value_name = "PATH")]
    pub path: Option<String>,
}

#[derive(Debug, Args)]
pub struct PipelineTemplateArgs {
    /// Template id: sentinel-app or aws-security [default: sentinel-app].
    #[arg(long = "id", value_name = "ID")]
    pub id: Option<String>,
    /// Template id (when --id is not given).
    #[arg(value_name = "ID")]
    pub template: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum QueueCommand {
    /// Print queue state counts as JSON.
    Inspect(DatabaseArgs),
    /// List dead-lettered events (metadata only).
    #[command(name = "dead-letters")]
    DeadLetters(DeadLettersArgs),
    /// Return dead-lettered events to the queue.
    Replay(ReplayArgs),
    /// Verify the tamper-evident queue ledger.
    Verify(QueueVerifyArgs),
}

#[derive(Debug, Args)]
pub struct DatabaseArgs {
    /// Queue database [default: ./data/bower.db].
    #[arg(long = "database", value_name = "FILE")]
    pub database: Option<String>,
}

#[derive(Debug, Args)]
pub struct DeadLettersArgs {
    #[command(flatten)]
    pub database: DatabaseArgs,
    /// Maximum records [default: 100].
    #[arg(long = "max", value_name = "N")]
    pub max: Option<String>,
}

#[derive(Debug, Args)]
pub struct ReplayArgs {
    #[command(flatten)]
    pub database: DatabaseArgs,
    /// Replay dead letters whose failure code starts with PREFIX.
    #[arg(long = "code", value_name = "PREFIX")]
    pub code: Option<String>,
    /// Replay a dead-lettered event id (repeatable).
    #[arg(long = "event", value_name = "ID")]
    pub events: Vec<String>,
    /// Maximum events [default: 1000].
    #[arg(long = "max", value_name = "N")]
    pub max: Option<String>,
}

#[derive(Debug, Args)]
pub struct QueueVerifyArgs {
    #[command(flatten)]
    pub database: DatabaseArgs,
    /// Fail when the ledger is behind or differs from a witnessed head.
    #[arg(long = "expect-head", value_name = "SEQUENCE:HASH")]
    pub expect_head: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum TestCommand {
    /// Send a synthetic canary event to a collector (sends BOWER_INGEST_TOKEN when set).
    Emit(EmitArgs),
}

#[derive(Debug, Args)]
pub struct EmitArgs {
    /// Collector base URL [default: http://127.0.0.1:4319].
    #[arg(long = "endpoint", value_name = "URL")]
    pub endpoint: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Generate a new ingest token; --id also prints a tokens-file line.
    Generate(TokenGenerateArgs),
}

#[derive(Debug, Args)]
pub struct TokenGenerateArgs {
    /// Producer id for the BOWER_INGEST_TOKENS_FILE line.
    #[arg(long = "id", value_name = "PRODUCER")]
    pub id: Option<String>,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Policy directory [default: policies/default].
    #[arg(long = "policy-directory", value_name = "DIR")]
    pub policy_directory: Option<String>,
    /// Signed pack to verify (repeatable).
    #[arg(long = "pack", value_name = "FILE")]
    pub packs: Vec<String>,
    /// Trusted public key for packs (repeatable).
    #[arg(long = "trusted-key", value_name = "PUB")]
    pub trusted_keys: Vec<String>,
    /// Privacy profile YAML.
    #[arg(long = "privacy-profile", value_name = "FILE")]
    pub privacy_profile: Option<String>,
    /// HMAC key file for the privacy profile.
    #[arg(long = "hmac-key-file", value_name = "FILE")]
    pub hmac_key_file: Option<String>,
    /// Live collector base URL.
    #[arg(long = "collector-url", value_name = "URL")]
    pub collector_url: Option<String>,
    /// Queue database whose ledger to verify.
    #[arg(long = "database", value_name = "FILE")]
    pub database: Option<String>,
    /// Logs Ingestion endpoint to check for region placement (repeatable).
    #[arg(long = "ingestion-endpoint", value_name = "URL")]
    pub ingestion_endpoints: Vec<String>,
    /// Deployed DCR resource id (read-only ARM check).
    #[arg(long = "dcr-resource-id", value_name = "ID")]
    pub dcr_resource_id: Option<String>,
    /// Log Analytics workspace resource id (read-only ARM check).
    #[arg(long = "workspace-resource-id", value_name = "ID")]
    pub workspace_resource_id: Option<String>,
    /// Azure credential: azure-cli, managed-identity, workload-identity or environment.
    #[arg(long = "credential", value_name = "MODE")]
    pub credential: Option<String>,
    /// Print checks as JSON.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum DcrCommand {
    /// Print or write the ARM template for the Bower table and DCR.
    Generate(DcrGenerateArgs),
    /// Compare a DCR (and optionally the table) with Bower's schema (exit 1 on error drift).
    Diff(DcrDiffArgs),
}

#[derive(Debug, Args)]
pub struct DcrGenerateArgs {
    /// Write the template to FILE instead of stdout.
    #[arg(long = "out", value_name = "FILE")]
    pub out: Option<String>,
    /// DCR name [default: bower-dcr].
    #[arg(long = "rule-name", value_name = "NAME")]
    pub rule_name: Option<String>,
    /// Table plan: Analytics or Basic [default: Analytics].
    #[arg(long = "plan", value_name = "PLAN")]
    pub plan: Option<String>,
    /// Interactive retention days [default: 90].
    #[arg(long = "retention-days", value_name = "N")]
    pub retention_days: Option<String>,
    /// Total retention days [default: 365].
    #[arg(long = "total-retention-days", value_name = "N")]
    pub total_retention_days: Option<String>,
}

#[derive(Debug, Args)]
pub struct DcrDiffArgs {
    /// DCR JSON file.
    #[arg(long = "rule", value_name = "FILE")]
    pub rule: Option<String>,
    /// Deployed DCR resource id (read-only ARM).
    #[arg(long = "dcr-resource-id", value_name = "ID")]
    pub dcr_resource_id: Option<String>,
    /// Table JSON file.
    #[arg(long = "table", value_name = "FILE")]
    pub table: Option<String>,
    /// Workspace resource id (reads the table via ARM).
    #[arg(long = "workspace-resource-id", value_name = "ID")]
    pub workspace_resource_id: Option<String>,
    /// Azure credential mode.
    #[arg(long = "credential", value_name = "MODE")]
    pub credential: Option<String>,
    /// `--dcr-resource-id` or `--workspace-resource-id` present, even without a value.
    #[arg(skip)]
    pub arm_requested: bool,
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Generate an ECDSA P-256 key pair (refuses to overwrite a private key).
    Generate(KeysGenerateArgs),
}

#[derive(Debug, Args)]
pub struct KeysGenerateArgs {
    /// Output directory (required).
    #[arg(long = "out-dir", value_name = "DIR")]
    pub out_dir: Option<String>,
    /// Key file base name [default: bower-signing].
    #[arg(long = "name", value_name = "NAME")]
    pub name: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PackCommand {
    /// Build and sign a pack from a source directory.
    Build(PackBuildArgs),
    /// Verify a pack signature and file hashes.
    Verify(PackFileArgs),
    /// Print pack metadata as JSON.
    Inspect(PackFileArgs),
    /// Run the pack's samples through its policies and privacy profile.
    Test(PackTestArgs),
    /// Policy population diff between two packs (exit 1 if a changed policy kept its version).
    Diff(PackDiffArgs),
}

#[derive(Debug, Args)]
pub struct PackBuildArgs {
    /// Pack source directory.
    #[arg(value_name = "DIR")]
    pub source: Option<String>,
    /// Private signing key PEM (required).
    #[arg(long = "key", value_name = "PRIVATE.pem")]
    pub key: Option<String>,
    /// Output directory [default: artifacts/packs].
    #[arg(long = "out", value_name = "DIR")]
    pub out: Option<String>,
}

#[derive(Debug, Args)]
pub struct PackFileArgs {
    /// Pack file (.bowerpack).
    #[arg(value_name = "FILE")]
    pub file: Option<String>,
    /// Trusted public key PEM (repeatable, at least one).
    #[arg(long = "trusted-key", value_name = "PUBLIC.pem")]
    pub trusted_keys: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PackTestArgs {
    #[command(flatten)]
    pub pack: PackFileArgs,
    /// HMAC key file for the pack's privacy profile.
    #[arg(long = "hmac-key-file", value_name = "FILE")]
    pub hmac_key_file: Option<String>,
    /// Run only this parser's raw samples (name or pack path).
    #[arg(long = "parser", value_name = "NAME")]
    pub parser: Option<String>,
    /// Write a machine-readable report for CI.
    #[arg(long = "report", value_name = "FILE")]
    pub report: Option<String>,
    /// Report format: json (default) or junit.
    #[arg(long = "report-format", value_name = "FORMAT")]
    pub report_format: Option<String>,
}

#[derive(Debug, Args)]
pub struct PackDiffArgs {
    /// OLD.bowerpack NEW.bowerpack
    #[arg(value_name = "PACK")]
    pub files: Vec<String>,
    /// Trusted public key PEM (repeatable, at least one).
    #[arg(long = "trusted-key", value_name = "PUBLIC.pem")]
    pub trusted_keys: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceCommand {
    /// Send a canary, query Sentinel for it and write a signed evidence bundle (exit 2 unless verified).
    Run(EvidenceRunArgs),
    /// Verify an evidence bundle signature.
    Verify(EvidenceVerifyArgs),
}

#[derive(Debug, Args)]
pub struct EvidenceRunArgs {
    /// Collector base URL (required). The ingest token is read from BOWER_INGEST_TOKEN.
    #[arg(long = "collector-url", value_name = "URL")]
    pub collector_url: Option<String>,
    /// Log Analytics workspace (customer) id; without it the bundle is simulated.
    #[arg(long = "workspace-id", value_name = "ID")]
    pub workspace_id: Option<String>,
    /// Workspace resource id for retention and region checks.
    #[arg(long = "workspace-resource-id", value_name = "ID")]
    pub workspace_resource_id: Option<String>,
    /// Destination table [default: BowerSecurity_CL].
    #[arg(long = "table", value_name = "NAME")]
    pub table: Option<String>,
    /// Azure credential mode.
    #[arg(long = "credential", value_name = "MODE")]
    pub credential: Option<String>,
    /// Managed identity client id.
    #[arg(long = "client-id", value_name = "ID")]
    pub client_id: Option<String>,
    /// Arrival query timeout in minutes [default: 15].
    #[arg(long = "timeout-minutes", value_name = "N")]
    pub timeout_minutes: Option<String>,
    /// Private key PEM used to sign the bundle.
    #[arg(long = "signing-key", value_name = "PRIVATE.pem")]
    pub signing_key: Option<String>,
    /// Bundle output file [default: bower-evidence-<time>.json].
    #[arg(long = "out", value_name = "FILE")]
    pub out: Option<String>,
    /// Probe profile: generic (default, /v1/events canary) or parser:PACK:INDEX.
    #[arg(long = "probe-profile", value_name = "PROFILE")]
    pub probe_profile: Option<String>,
}

#[derive(Debug, Args)]
pub struct EvidenceVerifyArgs {
    /// Evidence bundle file.
    #[arg(value_name = "FILE")]
    pub file: Option<String>,
    /// Trusted public key PEM (repeatable).
    #[arg(long = "trusted-key", value_name = "PUBLIC.pem")]
    pub trusted_keys: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum DeveloperCommand {
    /// Add Bower telemetry docs, configuration, catalogue and an AGENTS.md section to a .NET repo.
    Init(DeveloperInitArgs),
}

#[derive(Debug, Args)]
pub struct DeveloperInitArgs {
    /// Repository root [default: current directory].
    #[arg(long = "path", value_name = "PATH")]
    pub path: Option<String>,
}
