//! Command handlers. Each returns the C# exit code or a [`CliError`] (exit 1).

pub mod azure;
pub mod content;
pub mod dcr;
pub mod developer;
pub mod doctor;
pub mod emit;
pub mod evidence;
pub mod keys;
pub mod pack;
pub mod pipeline;
pub mod policy;
pub mod privacy;
pub mod queue;
pub mod token;

use std::future::Future;
use std::time::Duration;

use crate::cli::{
    Command, DcrCommand, DeveloperCommand, EvidenceCommand, KeysCommand, PackCommand,
    PipelineCommand, PolicyCommand, PrivacyCommand, QueueCommand, TestCommand, TokenCommand,
};
use crate::support::{CliError, CliResult};

pub fn dispatch(command: Command) -> CliResult {
    match command {
        Command::Version => {
            println!("bower 0.1.0");
            Ok(0)
        }
        Command::Validate(args) => content::validate(args.policy_directory.as_deref()),
        Command::Pipeline(PipelineCommand::Validate(args)) => pipeline::validate(&args),
        Command::Pipeline(PipelineCommand::Template(args)) => pipeline::template(&args),
        Command::Queue(QueueCommand::Inspect(args)) => queue::inspect(&args),
        Command::Queue(QueueCommand::DeadLetters(args)) => queue::dead_letters(&args),
        Command::Queue(QueueCommand::Replay(args)) => queue::replay(&args),
        Command::Queue(QueueCommand::Verify(args)) => queue::verify(&args),
        Command::Test(TestCommand::Emit(args)) => emit::run(&args),
        Command::Token(TokenCommand::Generate(args)) => token::generate(&args),
        Command::Doctor(args) => doctor::run(&args),
        Command::Dcr(DcrCommand::Generate(args)) => dcr::generate(&args),
        Command::Dcr(DcrCommand::Diff(args)) => dcr::diff(&args),
        Command::Keys(KeysCommand::Generate(args)) => keys::generate(&args),
        Command::Pack(PackCommand::Build(args)) => pack::build(&args),
        Command::Pack(PackCommand::Verify(args)) => pack::verify(&args),
        Command::Pack(PackCommand::Inspect(args)) => pack::inspect(&args),
        Command::Pack(PackCommand::Test(args)) => pack::test(&args),
        Command::Pack(PackCommand::Diff(args)) => pack::diff(&args),
        Command::Evidence(EvidenceCommand::Run(args)) => evidence::run(&args),
        Command::Evidence(EvidenceCommand::Verify(args)) => evidence::verify(&args),
        Command::Developer(DeveloperCommand::Init(args)) => developer::init(&args),
        Command::Privacy(PrivacyCommand::Validate(args)) => privacy::validate(&args),
        Command::Policy(PolicyCommand::Test(args)) => policy::test(&args),
    }
}

/// Runs async HTTP work on a single-threaded runtime.
pub fn block_on<T>(future: impl Future<Output = CliResult<T>>) -> CliResult<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::from_display)?
        .block_on(future)
}

/// The .NET `HttpClient` timeout message (`TaskCanceledException` wrapping a
/// `TimeoutException`), which both CLIs report as a failure, never a crash.
pub fn timeout_message(timeout: Duration) -> String {
    format!(
        "The request was canceled due to the configured HttpClient.Timeout of {} seconds elapsing.",
        timeout.as_secs_f64()
    )
}

/// HTTP failure as a CLI error (see [`http_error_with_host`]).
pub fn http_error(error: &reqwest::Error, timeout: Duration) -> CliError {
    CliError(http_error_with_host(error, timeout))
}

/// HTTP failure text shaped like .NET `HttpRequestException` messages, e.g.
/// `Connection refused (127.0.0.1:4319)`. Uses the innermost cause only, so
/// never headers or tokens.
pub fn http_error_with_host(error: &reqwest::Error, timeout: Duration) -> String {
    if error.is_timeout() {
        return timeout_message(timeout);
    }
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message = cause.to_string();
        source = cause.source();
    }
    if let Some(start) = message.find(" (os error ") {
        message.truncate(start);
    }
    if error.is_connect()
        && let Some(url) = error.url()
        && let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default())
    {
        return format!("{message} ({host}:{port})");
    }
    message
}
