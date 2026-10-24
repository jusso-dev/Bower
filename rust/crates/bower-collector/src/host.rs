//! Composition root (C# `CollectorApplication`). Kept in the library so integration
//! tests host the same application in-process; `main` stays a thin entry point.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use bower_contracts::time::Clock;
use bower_contracts::{
    DeliveryResult, DurableEventStore, EventRedactor, OutputAdapter, QueuedEvent,
    TelemetryPolicyEvaluator,
};
use bower_core::{CollectorIdentity, ProcessError, SecurityEventProcessor};
use bower_output_ama_spool::{AmaSpoolOptions, AmaSpoolOutput};
use bower_output_azure::{AzureLogsIngestionOptions, AzureLogsIngestionOutput, TokenProvider};
use bower_persistence::SqliteEventStore;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::app::{
    AppState, BundleInfo, EventProcessor, PolicyReference, ProcessFailure, ProcessingOutcome,
    router,
};
use crate::auth::IngestAuthentication;
use crate::error::HostError;
use crate::heartbeat::{AccessTokenSource, ManagementHeartbeat};
use crate::jobs::{
    JobCatalog, JobFn, JobScheduler, MANAGED_PRIVACY_PROFILE_JOB_ID, MANAGEMENT_HEARTBEAT_JOB_ID,
    QUEUE_MAINTENANCE_JOB_ID, QUEUE_RETENTION_JOB_ID, Schedule, run_queue_maintenance,
    run_queue_retention,
};
use crate::managed_privacy::ManagedPrivacyProfileJob;
use crate::rate_limit::TokenBucket;
use crate::settings::CollectorSettings;
use crate::shutdown::{ApplicationLifetime, ShutdownToken};
use crate::worker::{QueueDeliveryOptions, QueueDeliveryWorker};

/// What the policy bundle contributes to the host: selection, redaction and the
/// status view.
pub struct LoadedBundle {
    pub info: BundleInfo,
    pub packs: Vec<bower_packs::LoadedPack>,
    pub redactor: Arc<dyn EventRedactor>,
    pub evaluator: Arc<dyn TelemetryPolicyEvaluator>,
}

type DeliverFuture<'a> = Pin<Box<dyn Future<Output = DeliveryResult> + Send + 'a>>;

/// Object-safe view of [`OutputAdapter`] so the host can hold any configured output.
pub trait DynOutputAdapter: Send + Sync {
    fn output_id(&self) -> &str;
    fn deliver_boxed<'a>(&'a self, events: &'a [QueuedEvent]) -> DeliverFuture<'a>;
}

impl<T: OutputAdapter> DynOutputAdapter for T {
    fn output_id(&self) -> &str {
        self.id()
    }

    fn deliver_boxed<'a>(&'a self, events: &'a [QueuedEvent]) -> DeliverFuture<'a> {
        Box::pin(self.deliver(events))
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
    lifetime: ApplicationLifetime,
    output: Option<BoxedOutput>,
    credential: Option<Arc<dyn AccessTokenSource>>,
    delivery: QueueDeliveryOptions,
    scheduler: Option<JobScheduler>,
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
    let store: Arc<dyn DurableEventStore> = Arc::new(
        SqliteEventStore::new(
            &settings.queue_path,
            settings.maximum_queue_bytes,
            Some(Arc::clone(&clock)),
        )
        .map_err(|error| HostError::new("InvalidOperationException", error.to_string()))?,
    );
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
    );
    let auth = Arc::new(IngestAuthentication::with_clock(
        settings.ingest_token.as_deref(),
        settings.ingest_tokens_file.as_deref(),
        Arc::clone(&clock),
    )?);
    let catalog = Arc::new(JobCatalog::default());
    let policy_hash = bundle.info.hash.clone();
    let privacy_profile_hash = bundle.info.privacy_profile_hash.clone();
    let state = AppState {
        processor: Arc::new(CoreProcessor {
            processor,
            identity,
        }),
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
        packs: Arc::new(bundle.packs),
        catalog: Arc::clone(&catalog),
    };
    let delivery = options.delivery.unwrap_or(QueueDeliveryOptions {
        maximum_delivery_attempts: settings.maximum_delivery_attempts,
        ..QueueDeliveryOptions::default()
    });
    Ok(Collector {
        router: router(state),
        store,
        catalog,
        clock,
        policy_hash,
        privacy_profile_hash,
        auth,
        lifetime: ApplicationLifetime::new(),
        output: options.output,
        credential: options.credential,
        delivery,
        scheduler: None,
        settings,
    })
}

impl Collector {
    /// Replaces the configured output (C# `Build(..., output: ...)`), before `run`.
    pub fn set_output(&mut self, output: Option<BoxedOutput>) {
        self.output = output;
    }

    /// Host lifetime (C# `IHostApplicationLifetime`): stops `run` gracefully and records
    /// whether a restart was requested (exit code 75).
    pub fn lifetime(&self) -> ApplicationLifetime {
        self.lifetime.clone()
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

        let mut scheduler = JobScheduler::new(Arc::clone(&self.catalog), Arc::clone(&self.clock));
        let (store, clock, retention) = (
            Arc::clone(&self.store),
            Arc::clone(&self.clock),
            self.settings.delivered_retention,
        );
        let retention_job: JobFn = Arc::new(move || {
            let (store, clock) = (Arc::clone(&store), Arc::clone(&clock));
            Box::pin(async move {
                run_queue_retention(store, clock, retention)
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
            .map(Arc::new)
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

            if self.settings.uses_managed_privacy_profile() {
                let sync = ManagedPrivacyProfileJob::from_settings(
                    &self.settings,
                    self.privacy_profile_hash.clone(),
                    credential,
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
            }
        }
        self.scheduler = Some(scheduler);
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
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        if let Some(scheduler) = self.scheduler.take() {
            tasks.extend(scheduler.spawn(&shutdown));
        }
        if let Some(output) = self.output.clone() {
            let worker = QueueDeliveryWorker::new(
                Arc::clone(&self.store),
                Arc::new(output),
                Arc::clone(&self.clock),
                self.delivery.clone(),
            );
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
