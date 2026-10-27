//! Composition root (C# `CollectorApplication`). Kept in the library so integration
//! tests host the same application in-process; `main` stays a thin entry point.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use bower_contracts::time::Clock;
use bower_contracts::{
    DeliveryResult, DurableEventStore, EventRedactor, OutputAdapter, OutputConcurrencySnapshot,
    QueuedEvent, TelemetryPolicyEvaluator,
};
use bower_core::source_expectations::{self, SourceExpectationsError};
use bower_core::{CollectorIdentity, PipelineTelemetry, ProcessError, SecurityEventProcessor};
use bower_output_ama_spool::{AmaSpoolOptions, AmaSpoolOutput};
use bower_output_azure::{AzureLogsIngestionOptions, AzureLogsIngestionOutput, TokenProvider};
use bower_persistence::{QueueArchive, SqliteEventStore};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::app::{
    AppState, BundleInfo, DeliveryStatus, EventProcessor, PolicyReference, ProcessFailure,
    ProcessingOutcome, router,
};
use crate::auth::IngestAuthentication;
use crate::error::HostError;
use crate::heartbeat::{AccessTokenSource, ManagementHeartbeat};
use crate::jobs::{
    JobCatalog, JobFn, JobScheduler, JobTriggers, MANAGED_PRIVACY_PROFILE_JOB_ID,
    MANAGEMENT_HEARTBEAT_JOB_ID, QUEUE_ARCHIVE_JOB_ID, QUEUE_MAINTENANCE_JOB_ID,
    QUEUE_RETENTION_JOB_ID, SOURCE_ACTIVITY_JOB_ID, Schedule, run_queue_archive,
    run_queue_maintenance, run_queue_retention, run_source_activity,
};
use crate::managed_privacy::{ManagedPrivacyProfileJob, ManagedPrivacyState};
use crate::management_commands::{CommandLedger, CommandProcessor, CommandWorker, VerifiedCommand};
use crate::rate_limit::TokenBucket;
use crate::settings::CollectorSettings;
use crate::shutdown::{ApplicationLifetime, ShutdownToken};
use crate::source_health::SourceHealth;
use crate::worker::{DeliveryActivity, QueueDeliveryOptions, QueueDeliveryWorker};

/// What the policy bundle contributes to the host: selection, redaction and the
/// status view.
pub struct LoadedBundle {
    pub info: BundleInfo,
    pub packs: Vec<bower_packs::LoadedPack>,
    pub redactor: Arc<dyn EventRedactor>,
    /// The privacy redactor behind `redactor`, for offline previews that read
    /// per-finding metadata (`bower policy diff`). Never values.
    pub privacy: Arc<bower_redaction::JsonEventRedactor>,
    pub evaluator: Arc<dyn TelemetryPolicyEvaluator>,
    /// Management mode: the verified cached assignment envelope the bundle loaded.
    pub managed_privacy: Option<crate::managed_privacy::VerifiedManagedPrivacyProfile>,
}

type DeliverFuture<'a> = Pin<Box<dyn Future<Output = DeliveryResult> + Send + 'a>>;

/// Object-safe view of [`OutputAdapter`] so the host can hold any configured output.
pub trait DynOutputAdapter: Send + Sync {
    fn output_id(&self) -> &str;
    fn deliver_boxed<'a>(&'a self, events: &'a [QueuedEvent]) -> DeliverFuture<'a>;
    fn concurrency_boxed(&self) -> Option<OutputConcurrencySnapshot>;
}

impl<T: OutputAdapter> DynOutputAdapter for T {
    fn output_id(&self) -> &str {
        self.id()
    }

    fn deliver_boxed<'a>(&'a self, events: &'a [QueuedEvent]) -> DeliverFuture<'a> {
        Box::pin(self.deliver(events))
    }

    fn concurrency_boxed(&self) -> Option<OutputConcurrencySnapshot> {
        self.concurrency_snapshot()
    }
}

#[derive(Clone)]
pub struct BoxedOutput(pub Arc<dyn DynOutputAdapter>);

impl OutputAdapter for BoxedOutput {
    fn id(&self) -> &str {
        self.0.output_id()
    }

    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        self.0.deliver_boxed(events).await
    }

    fn concurrency_snapshot(&self) -> Option<OutputConcurrencySnapshot> {
        self.0.concurrency_boxed()
    }
}

/// Adapts bower-core's processor to the router seam, stamping the per-producer
/// source adapter (`local-http:<producer>`).
struct CoreProcessor {
    processor: SecurityEventProcessor,
    identity: CollectorIdentity,
}

impl EventProcessor for CoreProcessor {
    fn process(
        &self,
        candidate_json: &str,
        source_adapter: &str,
    ) -> Result<ProcessingOutcome, ProcessFailure> {
        let identity = CollectorIdentity {
            source_adapter: source_adapter.to_string(),
            ..self.identity.clone()
        };
        match self.processor.process(candidate_json, &identity) {
            Ok(result) => Ok(ProcessingOutcome {
                action: result.action,
                event_id: result.event_id,
                queued: result.queued,
                duplicate: result.duplicate,
                reasons: result.reasons,
                policy: result.policy_decision.map(|decision| PolicyReference {
                    policy_id: decision.policy_id,
                    policy_version: decision.policy_version,
                    policy_hash: decision.policy_hash,
                    score: decision.score,
                }),
                suppressed: result.suppressed,
            }),
            Err(ProcessError::Store(error)) => Err(error.into()),
            Err(ProcessError::Serialization(_)) => Err(ProcessFailure::Other("JsonException")),
        }
    }
}

/// Optional overrides (C# `Build(settings, configure, output, credential)`).
#[derive(Default)]
pub struct BuildOptions {
    pub clock: Option<Arc<dyn Clock>>,
    pub output: Option<BoxedOutput>,
    pub credential: Option<Arc<dyn AccessTokenSource>>,
    pub delivery: Option<QueueDeliveryOptions>,
}

pub struct Collector {
    pub settings: CollectorSettings,
    pub router: Router,
    pub store: Arc<dyn DurableEventStore>,
    pub catalog: Arc<JobCatalog>,
    pub clock: Arc<dyn Clock>,
    pub policy_hash: String,
    /// Active privacy profile content hash; `None` for the built-in default.
    pub privacy_profile_hash: Option<String>,
    pub auth: Arc<IngestAuthentication>,
    /// Management-mode ingest gate and status (local mode: never gates).
    pub managed_privacy: Arc<ManagedPrivacyState>,
    /// Selection counters and source activity (`PipelineTelemetry`).
    pub telemetry: Arc<PipelineTelemetry>,
    pub source_health: Arc<SourceHealth>,
    /// Long-term archive when `BOWER_ARCHIVE_PATH` is set.
    pub archive: Option<Arc<QueueArchive>>,
    sqlite: Arc<SqliteEventStore>,
    processor: SecurityEventProcessor,
    identity: CollectorIdentity,
    lifetime: ApplicationLifetime,
    output: Option<BoxedOutput>,
    /// Status view of `output` (adaptive request concurrency).
    delivery_status: Arc<DeliveryStatus>,
    credential: Option<Arc<dyn AccessTokenSource>>,
    delivery: QueueDeliveryOptions,
    scheduler: Option<JobScheduler>,
    /// Last output acknowledgement, reported on the heartbeat.
    pub delivery_activity: Arc<DeliveryActivity>,
    /// Management mode: the heartbeat v2 command processor and its durable ledger.
    pub commands: Option<Arc<CommandProcessor>>,
    command_inbox: Option<mpsc::Receiver<VerifiedCommand>>,
    /// Management mode: one client (proxy, CA bundle) built at start-up.
    management_client: Option<reqwest::Client>,
    /// Token enrolment (`BOWER_MANAGEMENT_AUTH=enrolment`): the key-bound credential.
    pub enrolment: Option<Arc<crate::enrolment::ManagementEnrolment>>,
    job_triggers: JobTriggers,
    /// Syslog listeners when `BOWER_SYSLOG_CONFIG` is set; bound by `initialize`.
    syslog: Option<bower_source_syslog::SyslogSource>,
    /// Live post-redaction tap; open streams end when the host stops.
    pub tap: Arc<crate::tap::EventTap>,
}

/// Wires settings, bundle, queue, processor, authentication and rate limiting.
pub fn build(
    settings: CollectorSettings,
    bundle: LoadedBundle,
    options: BuildOptions,
) -> Result<Collector, HostError> {
    settings.validate()?;
    let clock = options
        .clock
        .unwrap_or_else(|| Arc::new(bower_contracts::time::SystemClock));
    let sqlite = Arc::new(
        SqliteEventStore::new(
            &settings.queue_path,
            settings.maximum_queue_bytes,
            Some(Arc::clone(&clock)),
        )
        .map_err(|error| HostError::new("InvalidOperationException", error.to_string()))?,
    );
    let store: Arc<dyn DurableEventStore> = sqlite.clone();
    let telemetry = Arc::new(PipelineTelemetry::new(Arc::clone(&clock)));
    // Live post-redaction tap (bower tap). In memory only; never persisted.
    let tap = Arc::new(crate::tap::EventTap::new(
        settings.tap_options(),
        Arc::clone(&clock),
    ));
    let identity = CollectorIdentity::new(
        settings.collector_id.clone(),
        settings.version.clone(),
        "local-http",
        settings.configuration_hash(),
    );
    let processor = SecurityEventProcessor::new(
        Arc::new(bower_packs::runtime::PackDetectionRedactor {
            inner: bundle.redactor,
            evaluator: Arc::clone(&bundle.evaluator),
            rules: bundle
                .packs
                .iter()
                .flat_map(|pack| pack.detections.iter().cloned())
                .collect(),
        }),
        bundle.evaluator,
        Arc::clone(&store),
        Arc::clone(&clock),
    )
    .with_telemetry(Arc::clone(&telemetry))
    .with_tap(Arc::clone(&tap) as Arc<dyn bower_core::TapSink>);
    let packs = Arc::new(bundle.packs);
    // Loaded at build so a malformed expectations file stops start-up.
    let expectations = settings
        .source_expectations_path
        .as_ref()
        .map(source_expectations::load_file)
        .transpose()
        .map_err(|error| {
            let kind = match &error {
                SourceExpectationsError::FileNotFound => "FileNotFoundException",
                SourceExpectationsError::InvalidData(_) => "InvalidDataException",
                SourceExpectationsError::Io(_) => "IOException",
            };
            HostError::new(kind, error.to_string())
        })?;
    let source_health = Arc::new(SourceHealth::new(
        expectations,
        Arc::clone(&telemetry),
        Arc::clone(&clock),
    ));
    let archive = settings
        .archive_path
        .as_ref()
        .map(|path| QueueArchive::new(path, &settings.collector_id, Some(Arc::clone(&clock))))
        .transpose()
        .map_err(|error| HostError::new("ArgumentException", error.to_string()))?
        .map(Arc::new);
    let auth = Arc::new(IngestAuthentication::with_clock(
        settings.ingest_token.as_deref(),
        settings.ingest_tokens_file.as_deref(),
        Arc::clone(&clock),
    )?);
    let catalog = Arc::new(JobCatalog::default());
    let policy_hash = bundle.info.hash.clone();
    let privacy_profile_hash = bundle.info.privacy_profile_hash.clone();
    // Management mode fails closed until the first sync resolves.
    let managed_privacy = Arc::new(if settings.uses_managed_privacy_profile() {
        ManagedPrivacyState::new(
            bundle.managed_privacy.as_ref(),
            settings.managed_privacy_allow_default,
        )
    } else {
        ManagedPrivacyState::local()
    });
    let delivery_status = Arc::new(DeliveryStatus::new(options.output.clone()));
    // Loaded and checked against the loaded packs at build so a bad file stops start-up.
    let syslog = settings
        .syslog_config_path
        .as_ref()
        .map(|path| crate::syslog::load(path, &packs))
        .transpose()?
        .map(|configuration| {
            bower_source_syslog::SyslogSource::new(
                configuration,
                Arc::new(crate::syslog::CollectorSyslogSink {
                    processor: processor.clone(),
                    identity: identity.clone(),
                    packs: Arc::clone(&packs),
                    managed_privacy: Arc::clone(&managed_privacy),
                    clock: Arc::clone(&clock),
                    telemetry: Arc::clone(&telemetry),
                    tap: Some(Arc::clone(&tap)),
                }),
                Some(Arc::clone(&clock)),
            )
        });
    let state = AppState {
        delivery: Arc::clone(&delivery_status),
        processor: Arc::new(CoreProcessor {
            processor: processor.clone(),
            identity: identity.clone(),
        }),
        telemetry: Arc::clone(&telemetry),
        source_health: Arc::clone(&source_health),
        store: Arc::clone(&store),
        auth: Arc::clone(&auth),
        authorization: Arc::new(crate::authorization::ProducerAuthorization::new(
            settings.producer_scopes_file.as_deref(),
            settings.single_trust_domain,
        )?),
        limiter: Arc::new(TokenBucket::new(
            u32::try_from(settings.ingest_requests_per_second).unwrap_or(1),
        )),
        bundle: Arc::new(bundle.info),
        packs,
        catalog: Arc::clone(&catalog),
        syslog: syslog
            .as_ref()
            .map(bower_source_syslog::SyslogSource::metrics),
        managed_privacy: Arc::clone(&managed_privacy),
        tap: Arc::clone(&tap),
        tap_access: Arc::new(crate::tap_http::TapAccess {
            loopback_listener: settings.is_loopback_listener(),
            producers: settings.tap_producers.clone(),
        }),
    };
    let delivery = options.delivery.unwrap_or(QueueDeliveryOptions {
        maximum_delivery_attempts: settings.maximum_delivery_attempts,
        ..QueueDeliveryOptions::default()
    });
    // Proxy password and CA bundle are read here, so a bad file stops start-up (C# Build).
    let management_client = settings
        .management_endpoint
        .as_ref()
        .map(|_| crate::management_http::client(&settings))
        .transpose()?;
    let (commands, command_inbox) = if settings.management_endpoint.is_some() {
        let ledger = Arc::new(CommandLedger::new(
            &settings.management_command_directory(),
            Arc::clone(&clock),
        ));
        let (sender, receiver) = mpsc::channel(crate::management_commands::INBOX_CAPACITY);
        (
            Some(Arc::new(CommandProcessor::new(
                &settings,
                ledger,
                sender,
                Arc::clone(&clock),
            ))),
            Some(receiver),
        )
    } else {
        (None, None)
    };
    let enrolment = management_client.as_ref().and_then(|client| {
        crate::enrolment::ManagementEnrolment::from_settings(
            &settings,
            policy_hash.clone(),
            client.clone(),
            Arc::clone(&clock),
        )
        .map(Arc::new)
    });
    // No Azure identity: management requests carry the enrolled credential's assertion.
    let credential = options.credential.or_else(|| {
        enrolment
            .as_ref()
            .map(|enrolment| crate::enrolment::token_source(Arc::clone(enrolment)))
    });
    Ok(Collector {
        router: router(state),
        store,
        catalog,
        clock,
        policy_hash,
        privacy_profile_hash,
        auth,
        managed_privacy,
        telemetry,
        source_health,
        archive,
        sqlite,
        processor,
        identity,
        lifetime: ApplicationLifetime::new(),
        output: options.output,
        delivery_status,
        credential,
        delivery,
        scheduler: None,
        delivery_activity: Arc::new(DeliveryActivity::default()),
        commands,
        command_inbox,
        management_client,
        enrolment,
        job_triggers: JobTriggers::default(),
        syslog,
        tap,
        settings,
    })
}

impl Collector {
    /// Replaces the configured output (C# `Build(..., output: ...)`), before `run`.
    pub fn set_output(&mut self, output: Option<BoxedOutput>) {
        self.delivery_status.set(output.clone());
        self.output = output;
    }

    /// Host lifetime (C# `IHostApplicationLifetime`): stops `run` gracefully and records
    /// whether a restart was requested (exit code 75).
    pub fn lifetime(&self) -> ApplicationLifetime {
        self.lifetime.clone()
    }

    /// Bound syslog endpoints by listener id (after `initialize`).
    pub fn syslog_endpoints(&self) -> std::collections::HashMap<String, std::net::SocketAddr> {
        self.syslog
            .as_ref()
            .map(|source| source.endpoints().clone())
            .unwrap_or_default()
    }

    /// Replaces the syslog retry delay (tests), before `initialize`.
    pub fn set_syslog_retry_delay(&mut self, delay: std::time::Duration) {
        self.syslog = self
            .syslog
            .take()
            .map(|source| source.with_retry_delay(delay));
    }

    /// Initialises storage and registers recurring jobs (C# `InitializeAsync`).
    pub async fn initialize(&mut self) -> Result<(), HostError> {
        if !self.auth.required() && !self.settings.is_loopback_listener() {
            warn!(
                "Collector ingest authentication is disabled on a non-loopback listener. \
                 Use BOWER_ALLOW_UNAUTHENTICATED_INGEST only on an isolated network."
            );
        }

        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.initialize())
            .await
            .map_err(|_| {
                HostError::new(
                    "InvalidOperationException",
                    "Queue initialisation panicked.",
                )
            })?
            .map_err(|error| HostError::new("InvalidOperationException", error.to_string()))?;
        let store = Arc::clone(&self.store);
        let activity = tokio::task::spawn_blocking(move || store.get_source_activity())
            .await
            .map_err(|_| {
                HostError::new(
                    "InvalidOperationException",
                    "Source activity read panicked.",
                )
            })?
            .map_err(|error| HostError::new("InvalidOperationException", error.to_string()))?;
        self.telemetry.load(activity);
        let (store, source_health) = (Arc::clone(&self.store), Arc::clone(&self.source_health));
        tokio::task::spawn_blocking(move || source_health.initialize(store.as_ref()))
            .await
            .map_err(|_| {
                HostError::new(
                    "InvalidOperationException",
                    "Source monitoring start panicked.",
                )
            })?
            .map_err(|error| HostError::new("InvalidOperationException", error.to_string()))?;

        let mut scheduler = JobScheduler::new(Arc::clone(&self.catalog), Arc::clone(&self.clock));
        // Superseded by the next run on failure; the in-memory set keeps unsaved changes.
        let (store, telemetry) = (Arc::clone(&self.store), Arc::clone(&self.telemetry));
        let activity_job: JobFn = Arc::new(move || {
            let (store, telemetry) = (Arc::clone(&store), Arc::clone(&telemetry));
            Box::pin(async move { run_source_activity(store, telemetry).await })
        });
        scheduler.add(SOURCE_ACTIVITY_JOB_ID, Schedule::Minutely, 0, activity_job);
        if let Some(archive) = &self.archive {
            let (sqlite, archive) = (Arc::clone(&self.sqlite), Arc::clone(archive));
            let archive_job: JobFn = Arc::new(move || {
                let (sqlite, archive) = (Arc::clone(&sqlite), Arc::clone(&archive));
                Box::pin(async move { run_queue_archive(sqlite, archive).await })
            });
            scheduler.add(QUEUE_ARCHIVE_JOB_ID, Schedule::Minutely, 0, archive_job);
        }

        let (store, clock, retention, archive) = (
            Arc::clone(&self.store),
            Arc::clone(&self.clock),
            self.settings.delivered_retention,
            self.archive
                .clone()
                .map(|archive| (archive, Arc::clone(&self.sqlite))),
        );
        let retention_job: JobFn = Arc::new(move || {
            let (store, clock, archive) = (Arc::clone(&store), Arc::clone(&clock), archive.clone());
            Box::pin(async move {
                run_queue_retention(store, clock, retention, archive)
                    .await
                    .map(|_| ())
            })
        });
        scheduler.add(QUEUE_RETENTION_JOB_ID, Schedule::Hourly, 3, retention_job);

        let store = Arc::clone(&self.store);
        let maintenance_job: JobFn = Arc::new(move || {
            let store = Arc::clone(&store);
            Box::pin(async move { run_queue_maintenance(store).await })
        });
        scheduler.add(
            QUEUE_MAINTENANCE_JOB_ID,
            Schedule::Daily(3),
            2,
            maintenance_job,
        );

        if self.settings.management_endpoint.is_some() {
            let credential = self.credential.clone().ok_or_else(|| {
                HostError::new(
                    "InvalidOperationException",
                    "A management credential is required.",
                )
            })?;
            let heartbeat = ManagementHeartbeat::from_settings(
                &self.settings,
                self.policy_hash.clone(),
                self.privacy_profile_hash.as_deref(),
                Arc::clone(&credential),
                Arc::clone(&self.store),
                Arc::clone(&self.catalog),
            )
            .map(|mut heartbeat| {
                heartbeat.source_health = Some(Arc::clone(&self.source_health));
                heartbeat.commands = self.commands.clone();
                heartbeat.delivery_activity = Some(Arc::clone(&self.delivery_activity));
                heartbeat.enrolment = self.enrolment.clone();
                heartbeat.telemetry = Some(Arc::clone(&self.telemetry));
                if let Some(client) = &self.management_client {
                    heartbeat.client = client.clone();
                }
                Arc::new(heartbeat)
            })
            .ok_or_else(|| {
                HostError::new(
                    "InvalidOperationException",
                    "Management HTTP client could not be created.",
                )
            })?;
            let heartbeat_job: JobFn = Arc::new(move || {
                let heartbeat = Arc::clone(&heartbeat);
                Box::pin(async move { heartbeat.run().await })
            });
            scheduler.add(
                MANAGEMENT_HEARTBEAT_JOB_ID,
                Schedule::Minutely,
                0,
                heartbeat_job,
            );
            if self.settings.uses_enrolment() {
                // Enrol (or report) straight away rather than at the next minute.
                scheduler.trigger(MANAGEMENT_HEARTBEAT_JOB_ID);
            }

            if self.settings.uses_managed_privacy_profile() {
                let sync = ManagedPrivacyProfileJob::from_settings(
                    &self.settings,
                    self.privacy_profile_hash.clone(),
                    credential,
                    Arc::clone(&self.managed_privacy),
                    self.lifetime.clone(),
                )
                .map(Arc::new)
                .ok_or_else(|| {
                    HostError::new(
                        "InvalidOperationException",
                        "Management HTTP client could not be created.",
                    )
                })?;
                // Idempotent: an unchanged assignment is a no-op; a failed run is retried
                // by the next scheduled occurrence with the current profile still active.
                let sync_job: JobFn = Arc::new(move || {
                    let sync = Arc::clone(&sync);
                    Box::pin(async move { sync.run().await })
                });
                scheduler.add(
                    MANAGED_PRIVACY_PROFILE_JOB_ID,
                    Schedule::Minutely,
                    0,
                    sync_job,
                );
                // Resolve immediately at start-up instead of waiting for the next minute:
                // register first (heartbeat), then fetch the assignment.
                scheduler.trigger(MANAGEMENT_HEARTBEAT_JOB_ID);
                scheduler.trigger(MANAGED_PRIVACY_PROFILE_JOB_ID);
            }
        }
        self.job_triggers = scheduler.triggers();
        self.scheduler = Some(scheduler);
        if let Some(source) = self.syslog.as_mut() {
            // A bind or TLS failure stops start-up (C# `SyslogIntakeService.StartAsync`).
            source.bind().await.map_err(|error| match error {
                bower_source_syslog::SourceError::Tls(_) => {
                    HostError::new("InvalidOperationException", error.to_string())
                }
                bower_source_syslog::SourceError::Bind(inner) => {
                    HostError::new("SocketException", inner.kind().to_string())
                }
            })?;
            for status in source.snapshot() {
                info!(
                    listener = status.id,
                    protocol = status.protocol,
                    endpoint = status.endpoint,
                    "Syslog listener listening."
                );
            }
        }
        Ok(())
    }

    /// Serves until `shutdown` (or a [`ApplicationLifetime`] stop request), then drains
    /// HTTP, stops the worker and jobs.
    pub async fn run(mut self, listeners: Vec<TcpListener>, shutdown: ShutdownToken) {
        let (trigger, merged) = crate::shutdown::channel();
        let stopping = self.lifetime.stopping();
        let merge = tokio::spawn(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                () = stopping.cancelled() => {}
            }
            trigger.cancel();
        });
        let shutdown = merged;
        // ApplicationStopping for tap streams, so graceful drain never waits on a tap.
        let (tap, tap_shutdown) = (Arc::clone(&self.tap), shutdown.clone());
        tokio::spawn(async move {
            tap_shutdown.cancelled().await;
            tap.stop();
        });
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        if let Some(scheduler) = self.scheduler.take() {
            tasks.extend(scheduler.spawn(&shutdown));
        }
        let (processor, identity, token) = (
            self.processor.clone(),
            self.identity.clone(),
            shutdown.clone(),
        );
        tasks.push(tokio::spawn(async move {
            crate::suppression_worker::run(processor, identity, token).await;
        }));
        if let (Some(commands), Some(inbox)) = (&self.commands, self.command_inbox.take()) {
            let worker = CommandWorker {
                ledger: Arc::clone(commands.ledger()),
                triggers: self.job_triggers.clone(),
                processor: self.processor.clone(),
                identity: self.identity.clone(),
                environment: self.settings.environment.clone(),
                clock: Arc::clone(&self.clock),
                lifetime: self.lifetime.clone(),
                enrolment: self.enrolment.clone(),
            };
            let token = shutdown.clone();
            tasks.push(tokio::spawn(async move { worker.run(inbox, token).await }));
        }
        if let Some(source) = self.syslog.take() {
            let stop = shutdown.receiver();
            tasks.push(tokio::spawn(source.run(stop)));
        }
        if let Some(output) = self.output.clone() {
            let worker = QueueDeliveryWorker::new(
                Arc::clone(&self.store),
                Arc::new(output),
                Arc::clone(&self.clock),
                self.delivery.clone(),
            )
            .with_activity(Arc::clone(&self.delivery_activity));
            let token = shutdown.clone();
            tasks.push(tokio::spawn(async move { worker.run(token).await }));
        }

        crate::server::serve(listeners, self.router.clone(), shutdown).await;

        let stop = async {
            for task in tasks {
                let _ = task.await;
            }
        };
        if tokio::time::timeout(crate::server::SHUTDOWN_TIMEOUT, stop)
            .await
            .is_err()
        {
            warn!("Background services did not stop within the shutdown timeout.");
        }
        merge.abort();
    }
}

/// The configured output (C# `CreateOutput`); `None` for `BOWER_OUTPUT=none`.
pub fn create_output(
    settings: &CollectorSettings,
    credential: Option<Arc<dyn TokenProvider>>,
) -> Result<Option<BoxedOutput>, HostError> {
    let output: Arc<dyn DynOutputAdapter> = match settings.output_type.as_str() {
        "none" => return Ok(None),
        "ama-spool" => Arc::new(
            AmaSpoolOutput::new(AmaSpoolOptions::new(
                "ama-spool",
                settings.collector_id.clone(),
                settings.stream_name.clone(),
                settings.ama_spool_path.join("active"),
                settings.ama_spool_path.join("ready"),
            ))
            .map_err(|error| HostError::new("InvalidOperationException", error.to_string()))?,
        ),
        "azure-logs-ingestion" => {
            let credential =
                credential.unwrap_or_else(|| crate::credential::from_settings(settings));
            azure_output(settings, credential)?
        }
        other => {
            return Err(HostError::new(
                "InvalidOperationException",
                format!("Unsupported BOWER_OUTPUT value: {other}"),
            ));
        }
    };
    Ok(Some(BoxedOutput(output)))
}

fn azure_output(
    settings: &CollectorSettings,
    credential: Arc<dyn TokenProvider>,
) -> Result<Arc<dyn DynOutputAdapter>, HostError> {
    let (Some(endpoint), Some(dcr)) = (
        settings.dce_endpoint.clone(),
        settings.dcr_immutable_id.clone(),
    ) else {
        return Err(HostError::new(
            "InvalidOperationException",
            "BOWER_DCE_ENDPOINT and BOWER_DCR_ID are required for azure-logs-ingestion.",
        ));
    };
    let options = AzureLogsIngestionOptions::new(
        "azure-logs-ingestion",
        endpoint,
        dcr,
        settings.stream_name.clone(),
    );
    let output = AzureLogsIngestionOutput::new(options, credential)
        .map_err(|error| HostError::new("InvalidOperationException", error.to_string()))?;
    Ok(Arc::new(output))
}
