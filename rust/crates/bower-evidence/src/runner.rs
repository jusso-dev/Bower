//! `EvidenceRunner`: proves delivery end to end. Emits a synthetic canary through the
//! real collector (redaction, policy, queue, output), then finds it in Sentinel with
//! a KQL query under a separate read-only identity. Never claims delivery without
//! that query.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bower_contracts::time::{Clock, SystemClock, Timestamp};
use bower_contracts::types::{event_categories, event_types};
use bower_contracts::{
    ActorContext, ActorType, ApplicationContext, CURRENT_SCHEMA_VERSION, EventResult,
    EventSeverity, RequestContext, SecurityEventEnvelope,
};
use bower_integrity::{DetachedSignature, canonical_json};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};

use crate::EvidenceError;
use crate::bundle::{
    ArrivalRecord, CURRENT_SCHEMA, CanaryRecord, EvidenceBundle, ProbeRecord, RetentionRecord,
    SignedEvidence, modes,
};
use crate::controls;
use crate::probe::{self, ParserProbeFixture, outcomes};

/// Boxed `Send` future, so the client traits stay object safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Rows from a Log Analytics query as column-name maps, or the query's error code.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct QueryRows {
    pub rows: Vec<Map<String, Value>>,
    pub error: Option<String>,
}

/// `ILogAnalyticsQuery`: read-only KQL against a workspace.
pub trait LogAnalyticsQuery: Send + Sync {
    fn query<'a>(
        &'a self,
        workspace_id: &'a str,
        kql: &'a str,
        timespan: Duration,
    ) -> BoxFuture<'a, Result<QueryRows, EvidenceError>>;
}

/// `IArmReader`: ARM GET; `None` when the resource does not exist or is not readable.
pub trait ArmReader: Send + Sync {
    fn get<'a>(
        &'a self,
        resource_id: &'a str,
        api_version: &'a str,
    ) -> BoxFuture<'a, Result<Option<Map<String, Value>>, EvidenceError>>;
}

/// Collector HTTP status and JSON object body (when the body is one).
pub type CollectorResponse = (u16, Option<Map<String, Value>>);

/// `ICanarySender`: posts the canary JSON to the collector; returns status and body.
pub trait CanarySender: Send + Sync {
    fn send<'a>(
        &'a self,
        collector: &'a reqwest::Url,
        token: Option<&'a str>,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>>;
}

/// `IParserProbeSender`: the collector calls a parser probe makes besides the canary post.
pub trait ParserProbeSender: Send + Sync {
    /// GET `v1/status` (bearer authenticated): pack versions, hashes and parser states.
    fn get_status<'a>(
        &'a self,
        collector: &'a reqwest::Url,
        token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>>;

    /// POST one raw record to `v1/packs/PACK/parsers/INDEX/events`.
    fn send_record<'a>(
        &'a self,
        collector: &'a reqwest::Url,
        token: Option<&'a str>,
        pack_id: &'a str,
        parser_index: i32,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>>;
}

/// `EvidenceOptions`. `workspace_id: None` runs in simulated mode.
#[derive(Clone)]
pub struct EvidenceOptions {
    pub collector_url: reqwest::Url,
    /// Collector ingest token. Secret: never logged (excluded from `Debug`).
    pub ingest_token: Option<String>,
    /// Log Analytics workspace (customer) id.
    pub workspace_id: Option<String>,
    /// Workspace ARM resource id, for retention and region readout.
    pub workspace_resource_id: Option<String>,
    pub table: String,
    pub application_name: String,
    pub environment: String,
    pub timeout: Duration,
    pub poll_interval: Duration,
    /// `generic` (default) or an opt-in `parser:PACK:INDEX` profile with a trusted fixture.
    pub probe_profile: String,
}

impl EvidenceOptions {
    /// C# defaults: `BowerSecurity_CL`, `BowerEvidence`, `production`, 15 minute
    /// timeout, 30 second poll interval, simulated (no workspace).
    pub fn new(collector_url: reqwest::Url) -> Self {
        Self {
            collector_url,
            ingest_token: None,
            workspace_id: None,
            workspace_resource_id: None,
            table: "BowerSecurity_CL".to_owned(),
            application_name: "BowerEvidence".to_owned(),
            environment: "production".to_owned(),
            timeout: Duration::from_secs(15 * 60),
            poll_interval: Duration::from_secs(30),
            probe_profile: probe::GENERIC.to_owned(),
        }
    }
}

impl fmt::Debug for EvidenceOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceOptions")
            .field("collector_url", &self.collector_url.as_str())
            .field(
                "ingest_token",
                &self.ingest_token.as_ref().map(|_| "<redacted>"),
            )
            .field("workspace_id", &self.workspace_id)
            .field("workspace_resource_id", &self.workspace_resource_id)
            .field("table", &self.table)
            .field("application_name", &self.application_name)
            .field("environment", &self.environment)
            .field("timeout", &self.timeout)
            .field("poll_interval", &self.poll_interval)
            .field("probe_profile", &self.probe_profile)
            .finish()
    }
}

const TABLE_API_VERSION: &str = bower_dcr::LOG_ANALYTICS_API_VERSION;

static TABLE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_]{0,62}$").expect("static regex"));

pub struct EvidenceRunner {
    sender: Arc<dyn CanarySender>,
    query: Option<Arc<dyn LogAnalyticsQuery>>,
    arm: Option<Arc<dyn ArmReader>>,
    clock: Arc<dyn Clock>,
    parser_sender: Option<Arc<dyn ParserProbeSender>>,
}

impl EvidenceRunner {
    pub fn new(
        sender: Arc<dyn CanarySender>,
        query: Option<Arc<dyn LogAnalyticsQuery>>,
        arm: Option<Arc<dyn ArmReader>>,
    ) -> Self {
        Self {
            sender,
            query,
            arm,
            clock: Arc::new(SystemClock),
            parser_sender: None,
        }
    }

    /// The collector client for parser probes (C# `parserSender`).
    pub fn with_parser_sender(mut self, sender: Arc<dyn ParserProbeSender>) -> Self {
        self.parser_sender = Some(sender);
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub async fn run(&self, options: &EvidenceOptions) -> Result<EvidenceBundle, EvidenceError> {
        if !TABLE_NAME.is_match(&options.table) {
            return Err(EvidenceError::InvalidArgument(
                "Table must be a Log Analytics table name such as BowerSecurity_CL.".to_owned(),
            ));
        }

        if options.probe_profile != probe::GENERIC {
            let fixture = probe::resolve_parser(&options.probe_profile)?;
            return self.run_parser_probe(options, fixture).await;
        }

        let query = match (&options.workspace_id, &self.query) {
            (Some(workspace), Some(query)) => Some((workspace.as_str(), query.as_ref())),
            _ => None,
        };
        let simulated = query.is_none();
        let sent_at = self.clock.utc_now();
        let event_id = format!("bower-canary-{}", uuid::Uuid::now_v7().simple());
        let canary = canary_event(&event_id, sent_at, options);
        let canary_json = bower_contracts::json::to_string(&canary).map_err(|_| {
            EvidenceError::InvalidData("Canary event could not be serialized.".to_owned())
        })?;

        let (status, body) = self
            .sender
            .send(
                &options.collector_url,
                options.ingest_token.as_deref(),
                canary_json,
            )
            .await?;
        let canary_record = CanaryRecord {
            event_id: event_id.clone(),
            sent_at,
            collector_host: options
                .collector_url
                .host_str()
                .unwrap_or_default()
                .to_owned(),
            collector_status: i32::from(status),
            collector_decision: body
                .as_ref()
                .and_then(|body| string_at(body.get("decision"))),
            policy_id: body.as_ref().and_then(|body| {
                string_at(body.get("policy").and_then(|policy| policy.get("policyId")))
            }),
        };
        let collector_accepted = matches!(status, 200 | 202);

        let mut limitations = vec![
            "Proves delivery for this canary at this time; it does not prove every event was delivered.".to_owned(),
            "Bundles hold metadata only: no event payloads or credentials.".to_owned(),
        ];

        let mut arrival =
            ArrivalRecord::not_found(options.workspace_id.clone(), options.table.clone());
        match query {
            None => limitations.push(
                "SIMULATED: no Sentinel query was run, so this bundle is not delivery evidence."
                    .to_owned(),
            ),
            Some(_) if !collector_accepted => {
                arrival.query_error = Some("collector-rejected-canary".to_owned())
            }
            Some((workspace, query)) => {
                arrival = self
                    .poll(query, workspace, options, &event_id, sent_at)
                    .await?
            }
        }

        let retention = self.read_retention(options).await?;
        let errors = match query {
            None => None,
            Some((workspace, query)) => read_ingestion_errors(query, workspace).await?,
        };
        let mode = if simulated {
            modes::SIMULATED
        } else if arrival.found {
            modes::VERIFIED
        } else {
            modes::FAILED
        };
        let controls = controls::map(mode, &arrival, retention.as_ref());
        Ok(EvidenceBundle {
            schema: CURRENT_SCHEMA.to_owned(),
            mode: mode.to_owned(),
            generated_at: self.clock.utc_now(),
            tool: "bower".to_owned(),
            canary: canary_record,
            arrival,
            retention,
            ingestion_errors_last_hour: errors,
            controls,
            limitations,
            probe: None,
        })
    }

    /// Opt-in parser probe (C# `RunParserProbeAsync`): reads the collector's loaded pack
    /// and policy configuration, posts the trusted fixture through the signed parser's
    /// HTTP intake, then queries the destination for exactly that event identity.
    /// Collector acceptance alone never verifies.
    async fn run_parser_probe(
        &self,
        options: &EvidenceOptions,
        fixture: ParserProbeFixture,
    ) -> Result<EvidenceBundle, EvidenceError> {
        let Some(sender) = &self.parser_sender else {
            return Err(EvidenceError::InvalidArgument(
                "The collector sender does not support parser probes.".to_owned(),
            ));
        };
        let query = match (&options.workspace_id, &self.query) {
            (Some(workspace), Some(query)) => Some((workspace.as_str(), query.as_ref())),
            _ => None,
        };
        let simulated = query.is_none();
        let sent_at = self.clock.utc_now();
        let event_id = format!("bower-probe-{}", uuid::Uuid::now_v7().simple());
        let token = options.ingest_token.as_deref();

        let mut outcome: Option<String> = None;
        let mut collector_policy_hash = None;
        let mut pack_version = None;
        let mut pack_hash = None;
        let mut parser_status = None;
        let (status_code, status) = sender.get_status(&options.collector_url, token).await?;
        let policy = status
            .as_ref()
            .and_then(|status| status.get("policy"))
            .and_then(Value::as_object);
        match policy {
            _ if matches!(status_code, 401 | 403) => {
                outcome = Some(outcomes::COLLECTOR_PERMISSION_DENIED.to_owned());
            }
            Some(policy) if status_code == 200 => {
                collector_policy_hash = probe::text(policy.get("hash"));
                let pack = policy
                    .get("packs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_object)
                    .find(|pack| probe::text(pack.get("id")).as_deref() == Some(fixture.pack_id));
                pack_version = pack.and_then(|pack| probe::text(pack.get("version")));
                pack_hash = pack.and_then(|pack| probe::text(pack.get("packHash")));
                let statuses = pack
                    .and_then(|pack| pack.get("parserStatuses"))
                    .and_then(Value::as_array);
                parser_status = match statuses.and_then(|statuses| {
                    usize::try_from(fixture.parser_index)
                        .ok()
                        .and_then(|index| statuses.get(index))
                }) {
                    Some(value) => probe::text(Some(value)),
                    None => Some("absent".to_owned()),
                };
                if parser_status.as_deref() != Some("active-local-json") {
                    outcome = Some(outcomes::PARSER_INACTIVE.to_owned());
                }
            }
            _ => outcome = Some(outcomes::COLLECTOR_STATUS_UNREADABLE.to_owned()),
        }

        let mut collector_status = 0;
        let mut body = None;
        if outcome.is_none() {
            let (status, response) = sender
                .send_record(
                    &options.collector_url,
                    token,
                    fixture.pack_id,
                    fixture.parser_index,
                    fixture.render(&event_id, sent_at),
                )
                .await?;
            collector_status = status;
            outcome = probe::classify(status, response.as_ref(), &event_id).map(str::to_owned);
            body = response;
        }

        let event_policy = body
            .as_ref()
            .and_then(|body| body.get("policy"))
            .and_then(Value::as_object);
        let policy_field =
            |name: &str| event_policy.and_then(|policy| probe::text(policy.get(name)));
        let canary_record = CanaryRecord {
            event_id: event_id.clone(),
            sent_at,
            collector_host: options
                .collector_url
                .host_str()
                .unwrap_or_default()
                .to_owned(),
            collector_status: i32::from(collector_status),
            collector_decision: body
                .as_ref()
                .and_then(|body| string_at(body.get("decision"))),
            policy_id: policy_field("policyId"),
        };

        let mut limitations = vec![
            format!(
                "Proves delivery for this probe through {} at this time; it does not prove the untested paths listed in the probe record or that every event was delivered.",
                fixture.path()
            ),
            "Bundles hold metadata only: no event payloads or credentials.".to_owned(),
        ];

        let mut arrival =
            ArrivalRecord::not_found(options.workspace_id.clone(), options.table.clone());
        let mut queried_at = None;
        if simulated {
            limitations.push(
                "SIMULATED: no Sentinel query was run, so this bundle is not delivery evidence."
                    .to_owned(),
            );
            outcome.get_or_insert_with(|| outcomes::ACCEPTED_NOT_VERIFIED.to_owned());
        }
        let outcome = match (outcome, query) {
            (Some(outcome), _) => {
                arrival.query_error = Some(outcome.clone());
                outcome
            }
            (None, Some((workspace, query))) => {
                let (polled, outcome, at) = self
                    .poll_probe(
                        (workspace, query),
                        options,
                        &event_id,
                        fixture,
                        policy_field("policyHash").as_deref(),
                        sent_at,
                    )
                    .await?;
                arrival = polled;
                queried_at = at;
                outcome.to_owned()
            }
            (None, None) => unreachable!("simulated probes always have an outcome"),
        };

        let retention = self.read_retention(options).await?;
        let errors = match query {
            None => None,
            Some((workspace, query)) => read_ingestion_errors(query, workspace).await?,
        };
        let mode = if simulated {
            modes::SIMULATED
        } else if outcome == outcomes::VERIFIED {
            modes::VERIFIED
        } else {
            modes::FAILED
        };
        let controls = controls::map(mode, &arrival, retention.as_ref());
        let record = ProbeRecord {
            profile: fixture.profile(),
            tested_path: format!(
                "POST {} -> parser -> privacy -> policy -> queue -> output -> {}",
                fixture.path(),
                options.table
            ),
            fixture: fixture.id.to_owned(),
            pack_id: fixture.pack_id.to_owned(),
            parser_index: fixture.parser_index,
            pack_version,
            pack_hash,
            parser_status,
            collector_policy_hash,
            event_id,
            expected_event_type: fixture.expected_event_type.to_owned(),
            event_policy_id: policy_field("policyId"),
            event_policy_version: policy_field("policyVersion"),
            event_policy_hash: policy_field("policyHash"),
            destination_workspace_id: options.workspace_id.clone(),
            destination_table: options.table.clone(),
            queried_at,
            outcome,
            untested_paths: probe::UNTESTED_PATHS
                .iter()
                .map(|path| (*path).to_owned())
                .collect(),
        };
        Ok(EvidenceBundle {
            schema: CURRENT_SCHEMA.to_owned(),
            mode: mode.to_owned(),
            generated_at: self.clock.utc_now(),
            tool: "bower".to_owned(),
            canary: canary_record,
            arrival,
            retention,
            ingestion_errors_last_hour: errors,
            controls,
            limitations,
            probe: Some(record),
        })
    }

    /// C# `PollProbeAsync`: only the exact probe id with the expected event type
    /// verifies; permission errors stop at once; at the deadline an empty answer is a
    /// missing row and a failed one a timeout or query failure.
    async fn poll_probe(
        &self,
        (workspace, query): (&str, &dyn LogAnalyticsQuery),
        options: &EvidenceOptions,
        event_id: &str,
        fixture: ParserProbeFixture,
        expected_policy_hash: Option<&str>,
        sent_at: Timestamp,
    ) -> Result<(ArrivalRecord, &'static str, Option<Timestamp>), EvidenceError> {
        let table = &options.table;
        let kql = format!(
            "{table}\n| where TimeGenerated > ago(1d)\n| where EventId == \"{event_id}\"\n\
             | project TimeGenerated, IngestionTime = ingestion_time(), EventId, EventType, PolicyHash\n| take 1"
        );
        let missing = |attempts: i32, error: String| ArrivalRecord {
            query: Some(kql.clone()),
            attempts,
            query_error: Some(error),
            ..ArrivalRecord::not_found(options.workspace_id.clone(), table.clone())
        };
        let deadline = self.clock.utc_now() + chrono_duration(options.timeout);
        let mut attempts = 0;
        let mut answered = false;
        loop {
            attempts += 1;
            let queried_at = self.clock.utc_now();
            let result = match query
                .query(workspace, &kql, Duration::from_secs(86_400))
                .await
            {
                Ok(result) => result,
                Err(EvidenceError::Http(message)) => QueryRows {
                    rows: Vec::new(),
                    error: Some(
                        if message.starts_with(crate::clients::TIMEOUT_MESSAGE) {
                            outcomes::QUERY_TIMEOUT_CODE
                        } else {
                            outcomes::QUERY_TRANSPORT_CODE
                        }
                        .to_owned(),
                    ),
                },
                Err(other) => return Err(other),
            };
            if let Some(error) = result
                .error
                .as_deref()
                .filter(|error| probe::is_permission_error(error))
            {
                return Ok((
                    missing(attempts, error.to_owned()),
                    outcomes::DESTINATION_PERMISSION_DENIED,
                    Some(queried_at),
                ));
            }
            if let (None, Some(row)) = (&result.error, result.rows.first()) {
                // Only the exact probe identity, with the event type the parser should map, verifies.
                if string_at(row.get("EventId")).as_deref() != Some(event_id)
                    || string_at(row.get("EventType")).as_deref()
                        != Some(fixture.expected_event_type)
                {
                    return Ok((
                        missing(attempts, outcomes::DESTINATION_WRONG_EVENT.to_owned()),
                        outcomes::DESTINATION_WRONG_EVENT,
                        Some(queried_at),
                    ));
                }
                // The row must carry the policy hash the collector reported for this probe;
                // otherwise the evidence would not identify the configuration it tested.
                let row_policy_hash = string_at(row.get("PolicyHash"));
                if row_policy_hash.as_deref() != expected_policy_hash {
                    return Ok((
                        ArrivalRecord {
                            row_policy_hash,
                            ..missing(attempts, outcomes::CONFIGURATION_MISMATCH.to_owned())
                        },
                        outcomes::CONFIGURATION_MISMATCH,
                        Some(queried_at),
                    ));
                }
                let generated = read_time(row, "TimeGenerated");
                let ingested = read_time(row, "IngestionTime");
                return Ok((
                    ArrivalRecord {
                        found: true,
                        workspace_id: options.workspace_id.clone(),
                        table: table.clone(),
                        query: Some(kql),
                        attempts,
                        time_generated: generated,
                        ingestion_time: ingested,
                        latency_seconds: ingested
                            .map(|ingested| latency_seconds(ingested, sent_at)),
                        row_policy_hash,
                        query_error: None,
                    },
                    outcomes::VERIFIED,
                    Some(queried_at),
                ));
            }

            answered |= result.error.is_none();
            if self.clock.utc_now() + chrono_duration(options.poll_interval) > deadline {
                // Any answered query means the destination was reachable and the row absent;
                // timeout or failure only when no query was ever answered.
                let outcome = match result.error.as_deref() {
                    _ if answered => outcomes::DESTINATION_ROW_MISSING,
                    None => outcomes::DESTINATION_ROW_MISSING,
                    Some(error) if probe::is_timeout_error(error) => outcomes::DESTINATION_TIMEOUT,
                    Some(_) => outcomes::DESTINATION_QUERY_FAILED,
                };
                let error = match result.error {
                    Some(error) if outcome != outcomes::DESTINATION_ROW_MISSING => error,
                    _ => outcome.to_owned(),
                };
                return Ok((missing(attempts, error), outcome, Some(queried_at)));
            }

            tokio::time::sleep(options.poll_interval).await;
        }
    }

    /// Signs the bundle's canonical JSON when a private key is supplied.
    pub fn sign(
        bundle: &EvidenceBundle,
        private_key_pem: Option<&str>,
    ) -> Result<SignedEvidence, EvidenceError> {
        let node = bundle.to_json();
        let signature = match private_key_pem {
            None => None,
            Some(pem) => Some(
                bower_integrity::sign(&canonical_json::bytes(&node), pem)
                    .map_err(|error| EvidenceError::Signing(error.to_string()))?,
            ),
        };
        let Value::Object(bundle) = node else {
            unreachable!("bundles serialize as objects")
        };
        Ok(SignedEvidence { bundle, signature })
    }

    /// True only for a signed bundle whose canonical JSON verifies under a trusted key.
    pub fn verify<'a, I>(evidence: &SignedEvidence, trusted_public_key_pems: I) -> bool
    where
        I: IntoIterator<Item = &'a str>,
    {
        let Some(signature) = &evidence.signature else {
            return false;
        };
        verify_signature(
            &Value::Object(evidence.bundle.clone()),
            signature,
            trusted_public_key_pems,
        )
    }

    async fn poll(
        &self,
        query: &dyn LogAnalyticsQuery,
        workspace: &str,
        options: &EvidenceOptions,
        event_id: &str,
        sent_at: Timestamp,
    ) -> Result<ArrivalRecord, EvidenceError> {
        let table = &options.table;
        let kql = format!(
            "{table}\n| where TimeGenerated > ago(1d)\n| where EventId == \"{event_id}\"\n\
             | project TimeGenerated, IngestionTime = ingestion_time(), EventId, PolicyHash\n| take 1"
        );
        let deadline = self.clock.utc_now() + chrono_duration(options.timeout);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let result = query
                .query(workspace, &kql, Duration::from_secs(86_400))
                .await?;
            if let Some(row) = result.rows.first() {
                let generated = read_time(row, "TimeGenerated");
                let ingested = read_time(row, "IngestionTime");
                return Ok(ArrivalRecord {
                    found: true,
                    workspace_id: options.workspace_id.clone(),
                    table: table.clone(),
                    query: Some(kql),
                    attempts,
                    time_generated: generated,
                    ingestion_time: ingested,
                    latency_seconds: ingested.map(|ingested| latency_seconds(ingested, sent_at)),
                    row_policy_hash: string_at(row.get("PolicyHash")),
                    query_error: None,
                });
            }

            if self.clock.utc_now() + chrono_duration(options.poll_interval) > deadline {
                return Ok(ArrivalRecord {
                    query: Some(kql),
                    attempts,
                    query_error: Some(
                        result
                            .error
                            .unwrap_or_else(|| "not-found-before-timeout".to_owned()),
                    ),
                    ..ArrivalRecord::not_found(options.workspace_id.clone(), table.clone())
                });
            }

            tokio::time::sleep(options.poll_interval).await;
        }
    }

    async fn read_retention(
        &self,
        options: &EvidenceOptions,
    ) -> Result<Option<RetentionRecord>, EvidenceError> {
        let (Some(arm), Some(resource_id)) = (
            &self.arm,
            options
                .workspace_resource_id
                .as_deref()
                .filter(|id| !id.trim().is_empty()),
        ) else {
            return Ok(None);
        };
        let workspace = arm.get(resource_id, TABLE_API_VERSION).await?;
        let table = arm
            .get(
                &format!("{resource_id}/tables/{}", options.table),
                TABLE_API_VERSION,
            )
            .await?;
        let properties = table
            .as_ref()
            .and_then(|table| table.get("properties"))
            .and_then(Value::as_object);
        Ok(Some(RetentionRecord {
            plan: properties.and_then(|properties| string_at(properties.get("plan"))),
            interactive_days: read_int(properties, "retentionInDays"),
            total_days: read_int(properties, "totalRetentionInDays"),
            workspace_region: workspace
                .as_ref()
                .and_then(|workspace| string_at(workspace.get("location"))),
        }))
    }
}

/// Verifies `signature` over the canonical bytes of `bundle`.
fn verify_signature<'a, I>(bundle: &Value, signature: &DetachedSignature, trusted: I) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    bower_integrity::verify(&canonical_json::bytes(bundle), signature, trusted)
}

fn canary_event(
    event_id: &str,
    sent_at: Timestamp,
    options: &EvidenceOptions,
) -> SecurityEventEnvelope {
    SecurityEventEnvelope {
        schema_version: CURRENT_SCHEMA_VERSION.to_owned(),
        event_id: event_id.to_owned(),
        event_original_id: Some(event_id.to_owned()),
        time_generated: sent_at,
        time_observed: None,
        event_category: event_categories::COLLECTOR_HEALTH.to_owned(),
        event_type: event_types::COLLECTOR_CANARY.to_owned(),
        event_action: "evidence.canary".to_owned(),
        event_result: EventResult::Success,
        event_severity: EventSeverity::Informational,
        event_outcome_reason: Some("Synthetic delivery-proof canary".to_owned()),
        application: ApplicationContext {
            name: options.application_name.clone(),
            version: None,
            environment: options.environment.clone(),
            instance: None,
            tenant_id: None,
        },
        actor: Some(ActorContext {
            username: Some("bower.evidence".to_owned()),
            actor_type: ActorType::System,
            ..ActorContext::default()
        }),
        target: None,
        source: None,
        request: Some(RequestContext {
            correlation_id: Some(event_id.to_owned()),
            ..RequestContext::default()
        }),
        change: None,
        security: None,
        collector: None,
        labels: Some(IndexMap::from([(
            "evidenceType".to_owned(),
            "canary".to_owned(),
        )])),
        attributes: None,
        privacy: None,
    }
}

/// DCRLogErrors only exists when DCR error logging is enabled; absence is not an error.
async fn read_ingestion_errors(
    query: &dyn LogAnalyticsQuery,
    workspace: &str,
) -> Result<Option<i64>, EvidenceError> {
    let result = query
        .query(
            workspace,
            "DCRLogErrors | where TimeGenerated > ago(1h) | summarize Errors = count()",
            Duration::from_secs(3_600),
        )
        .await?;
    if result.error.is_some() {
        return Ok(None);
    }
    Ok(result
        .rows
        .first()
        .and_then(|row| row.get("Errors"))
        .and_then(Value::as_i64))
}

/// `JsonNode.GetValue<string>()` on a string node; other kinds read as absent.
fn string_at(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

/// `DateTimeOffset.TryParse(text, InvariantCulture, AssumeUniversal)` on a string cell.
fn read_time(row: &Map<String, Value>, column: &str) -> Option<Timestamp> {
    row.get(column)
        .and_then(Value::as_str)
        .and_then(bower_contracts::time::parse)
}

/// `JsonValue.TryGetValue(out int)`.
fn read_int(properties: Option<&Map<String, Value>>, name: &str) -> Option<i32> {
    properties
        .and_then(|properties| properties.get(name))
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
}

/// `Math.Round((ingested - sentAt).TotalSeconds, 1)`: tick-precise seconds, rounded
/// half to even at one decimal as .NET does.
pub fn latency_seconds(ingested: Timestamp, sent_at: Timestamp) -> f64 {
    let delta = ingested - sent_at;
    let ticks = delta.num_seconds() as f64 * 10_000_000.0 + f64::from(delta.subsec_nanos() / 100);
    let seconds = ticks / 10_000_000.0;
    (seconds * 10.0).round_ties_even() / 10.0
}

fn chrono_duration(duration: Duration) -> chrono::TimeDelta {
    chrono::TimeDelta::from_std(duration).unwrap_or(chrono::TimeDelta::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_rounds_like_math_round() {
        let sent = bower_contracts::time::parse("2026-07-26T02:14:19Z").unwrap();
        let ingested = bower_contracts::time::parse("2026-07-26T02:16:19.25Z").unwrap();
        assert_eq!(latency_seconds(ingested, sent), 120.2);
        let ingested = bower_contracts::time::parse("2026-07-26T02:14:19.35Z").unwrap();
        assert_eq!(latency_seconds(ingested, sent), 0.4);
        let earlier = bower_contracts::time::parse("2026-07-26T02:14:18.5Z").unwrap();
        assert_eq!(latency_seconds(earlier, sent), -0.5);
    }
}
