//! `bootstrap` for the `provided.al2023` runtime. Settings, the policy bundle and
//! the privacy HMAC key are loaded once per execution environment; any failure
//! is an init error, so the function never serves with a partial configuration.

use std::sync::Arc;

use bower_lambda::aws::{CloudTrailLakeSink, fetch_hmac_key, sdk_config};
use bower_lambda::{Handler, LambdaSettings};
use lambda_runtime::{Error, LambdaEvent, service_fn};
use serde_json::value::RawValue;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // CloudWatch adds timestamps; logs carry metadata only.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .init();

    let settings = LambdaSettings::from_process_environment()?;
    let config = sdk_config().await;
    let key = match &settings.privacy_hmac_key_secret_arn {
        Some(arn) => Some(fetch_hmac_key(&config, arn).await?),
        None => None,
    };
    let sink = CloudTrailLakeSink::new(
        &config,
        settings.channel_arn.clone(),
        settings.external_id.clone(),
    );
    let handler = Arc::new(Handler::new(
        &settings,
        key.as_deref(),
        sink,
        Arc::new(bower_contracts::time::SystemClock),
    )?);
    drop(key);
    info!(
        ingress = settings.ingress.name(),
        hmac_key = settings.privacy_hmac_key_secret_arn.is_some(),
        "Bower Lambda initialised."
    );

    lambda_runtime::run(service_fn(move |event: LambdaEvent<Box<RawValue>>| {
        let handler = Arc::clone(&handler);
        async move {
            let payload = handler.invoke(event.payload.get()).await.into_payload();
            RawValue::from_string(payload).map_err(Error::from)
        }
    }))
    .await
}
