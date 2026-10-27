//! `bower`: Rust port of the C# Bower CLI (`src/Bower.Cli`).
//!
//! Commands, options, defaults, output text and exit codes follow the C# CLI:
//! 0 success, 1 failure (message on stderr), 2 where C# returns 2 (invalid
//! pipeline, failed test emit, non-verified evidence). Status commands print
//! metadata only, never secrets, tokens or payloads.

mod args;
mod cli;
mod commands;
mod output;
mod support;

use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;

use crate::cli::Cli;

/// `bower --help` text, verbatim from the C# `WriteHelp`.
pub const HELP: &str = "Bower security telemetry

Commands:
  bower validate [--policy-directory PATH]
  bower pipeline validate --file PATH
  bower pipeline template [--id sentinel-app|aws-security]
  bower queue inspect [--database PATH]
  bower test emit [--endpoint URL]      (sends BOWER_INGEST_TOKEN when set)
  bower token generate [--id PRODUCER] (new ingest token; --id prints a tokens-file line)

  bower doctor [--policy-directory DIR] [--pack FILE --trusted-key PUB] [--privacy-profile FILE]
               [--hmac-key-file FILE] [--collector-url URL] [--database FILE]
               [--ingestion-endpoint URL] [--dcr-resource-id ID] [--workspace-resource-id ID]
               [--credential azure-cli|managed-identity|workload-identity|environment] [--json]

  bower dcr generate [--out FILE] [--rule-name NAME] [--retention-days N] [--total-retention-days N]
  bower dcr diff (--rule FILE | --dcr-resource-id ID) [--table FILE | --workspace-resource-id ID]

  bower keys generate --out-dir DIR [--name NAME]
  bower pack build DIR --key PRIVATE.pem [--out DIR]
  bower pack verify|inspect|test FILE --trusted-key PUBLIC.pem
        [--hmac-key-file FILE] [--parser NAME] [--report FILE [--report-format json|junit]] (test)
  bower pack diff OLD.bowerpack NEW.bowerpack --trusted-key PUBLIC.pem

  bower evidence run --collector-url URL [--workspace-id ID --workspace-resource-id ID]
                     [--table NAME] [--signing-key PRIVATE.pem] [--out FILE]
                     [--probe-profile generic|parser:PACK:INDEX]
  bower evidence verify FILE --trusted-key PUBLIC.pem

  bower queue dead-letters --database FILE
  bower queue replay --database FILE (--code PREFIX | --event ID ...)
  bower queue verify --database FILE [--expect-head SEQUENCE:HASH]
  bower developer init [--path PATH]
  bower privacy validate FILE [--hmac-key-file FILE] [--sample FILE]
  bower policy test EVENT.json... [--policy-directory DIR] [--pack FILE --trusted-key PUB]
        [--privacy-profile FILE --hmac-key-file FILE] [--expect DECISION]
  bower policy diff --baseline DIR --candidate DIR EVENT.json... [--fail-on-change]
        [--baseline-pack FILE --baseline-trusted-key PUB] [--baseline-privacy-profile FILE]
        [--baseline-hmac-key-file FILE] [--baseline-hmac-key-id ID] (same for --candidate-*) [--at ISO]
  bower archive create --archive DIR [--database FILE] [--collector-id ID]
  bower archive verify --archive DIR [--anchor SEQUENCE:HASH]
  bower archive replay --archive DIR --collector-url URL [--from ISO] [--to ISO]
                       [--event-type TYPE]... [--dry-run]
  bower sources check --expectations FILE [--database FILE]
  bower tap [--collector URL] [--stage redacted|decided|queued] [--source APP] [--event-type TYPE]
            [--limit N] [--duration SECONDS] [--sample N]   (post-redaction JSON lines on stdout)
  bower top [--collector URL] [--interval SECONDS] [--once] [--iterations N]
  bower version";

const UNKNOWN_COMMAND: &str = "Unknown command. Run 'bower --help'.";

fn run(args: Vec<String>) -> i32 {
    let rest = &args[1.min(args.len())..];
    if matches!(rest, [])
        || matches!(rest, [only] if only == "--help" || only == "-h" || only == "help")
    {
        println!("{HELP}");
        return 0;
    }
    if rest
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        return command_help(rest);
    }

    let Some(command) = args::parse(rest) else {
        eprintln!("{UNKNOWN_COMMAND}");
        return 1;
    };
    match commands::dispatch(command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

/// `bower <command> [<subcommand>] --help`: clap help for the longest leading
/// command path it recognises. (The C# CLI has no per-command help.)
fn command_help(rest: &[String]) -> i32 {
    let path: Vec<&str> = rest
        .iter()
        .take_while(|argument| !argument.starts_with('-'))
        .take(2)
        .map(String::as_str)
        .collect();
    for length in (1..=path.len()).rev() {
        let argv = std::iter::once("bower")
            .chain(path[..length].iter().copied())
            .chain(std::iter::once("--help"));
        if let Err(error) = Cli::try_parse_from(argv)
            && error.kind() == ErrorKind::DisplayHelp
        {
            print!("{}", error.render());
            return 0;
        }
    }
    eprintln!("{UNKNOWN_COMMAND}");
    1
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args_os()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let code = run(args);
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
