//! C#-compatible argument handling (`Program.RunAsync` pattern match plus
//! `CliOptions`). Clap only renders `--help`; commands are recognised and options
//! read exactly like the C# CLI so the same command lines behave the same:
//! unknown options and extra arguments are ignored, the first occurrence of an
//! option wins, an option with no following value is absent, and a value may
//! start with `-`. Positional arguments (pack, bundle and pipeline files, template
//! ids) skip every `--option` together with the argument after it, so neither a
//! known option's value nor an unknown option's value is taken as the positional.

use crate::cli::{
    ArchiveCommand, ArchiveCreateArgs, ArchiveReplayArgs, ArchiveVerifyArgs, PolicyDiffArgs,
    SourcesCheckArgs, SourcesCommand,
};
use crate::cli::{
    Command, DatabaseArgs, DcrCommand, DcrDiffArgs, DcrGenerateArgs, DeadLettersArgs,
    DeveloperCommand, DeveloperInitArgs, DoctorArgs, EmitArgs, EvidenceCommand, EvidenceRunArgs,
    EvidenceVerifyArgs, KeysCommand, KeysGenerateArgs, PackBuildArgs, PackCommand, PackDiffArgs,
    PackFileArgs, PackTestArgs, PipelineCommand, PipelineTemplateArgs, PipelineValidateArgs,
    PolicyCommand, PolicyTestArgs, PrivacyCommand, PrivacyValidateArgs, QueueCommand,
    QueueVerifyArgs, ReplayArgs, TestCommand, TokenCommand, TokenGenerateArgs, ValidateArgs,
};

/// `CliOptions` over one command's remaining arguments.
#[derive(Clone, Copy, Debug)]
pub struct Options<'a>(pub &'a [String]);

impl<'a> Options<'a> {
    /// `CliOptions.Get`: the argument after the first `name`, if any.
    pub fn get(self, name: &str) -> Option<String> {
        let index = self.0.iter().position(|argument| argument == name)?;
        self.0.get(index + 1).cloned()
    }

    /// `CliOptions.All`: every value following `name`.
    pub fn all(self, name: &str) -> Vec<String> {
        self.0
            .windows(2)
            .filter(|pair| pair[0] == name)
            .map(|pair| pair[1].clone())
            .collect()
    }

    /// `CliOptions.Has`.
    pub fn has(self, name: &str) -> bool {
        self.0.iter().any(|argument| argument == name)
    }

    /// `CliOptions.Positional`: first argument that is not a `--option` or its value.
    pub fn positional(self) -> Option<String> {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index].starts_with("--") {
                index += 2;
                continue;
            }
            return Some(self.0[index].clone());
        }
        None
    }

    /// Every argument that is not a `--option` or its value (`policy test` files).
    pub fn positionals(self) -> Vec<String> {
        let mut values = Vec::new();
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index].starts_with("--") {
                index += 2;
                continue;
            }
            values.push(self.0[index].clone());
            index += 1;
        }
        values
    }

    /// `pack diff`: arguments ending with `.bowerpack` (ordinal, case-insensitive).
    pub fn bowerpacks(self) -> Vec<String> {
        self.0
            .iter()
            .filter(|argument| argument.to_ascii_lowercase().ends_with(".bowerpack"))
            .cloned()
            .collect()
    }
}

/// Recognises a command line (without the program name) the way the C#
/// `args switch` does. `None` means "Unknown command".
pub fn parse(args: &[String]) -> Option<Command> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (command, rest): (&[&str], &[String]) = match words.as_slice() {
        ["version"] => return Some(Command::Version),
        [first, second, ..]
            if matches!(
                (*first, *second),
                ("pipeline", "validate" | "template")
                    | ("queue", "inspect" | "dead-letters" | "replay" | "verify")
                    | ("test", "emit")
                    | ("token", "generate")
                    | ("dcr", "generate" | "diff")
                    | ("keys", "generate")
                    | ("pack", "build" | "verify" | "inspect" | "test" | "diff")
                    | ("evidence", "run" | "verify")
                    | ("developer", "init")
                    | ("privacy", "validate")
                    | ("policy", "test" | "diff")
                    | ("archive", "create" | "verify" | "replay")
                    | ("sources", "check")
            ) =>
        {
            (&words[..2], &args[2..])
        }
        [first, ..] if matches!(*first, "validate" | "doctor") => (&words[..1], &args[1..]),
        _ => return None,
    };
    let o = Options(rest);
    let database = || DatabaseArgs {
        database: o.get("--database"),
    };
    let pack_file = || PackFileArgs {
        file: o.positional(),
        trusted_keys: o.all("--trusted-key"),
    };
    Some(match command {
        ["validate"] => Command::Validate(ValidateArgs {
            policy_directory: o.get("--policy-directory"),
        }),
        ["doctor"] => Command::Doctor(DoctorArgs {
            policy_directory: o.get("--policy-directory"),
            packs: o.all("--pack"),
            trusted_keys: o.all("--trusted-key"),
            privacy_profile: o.get("--privacy-profile"),
            hmac_key_file: o.get("--hmac-key-file"),
            collector_url: o.get("--collector-url"),
            database: o.get("--database"),
            ingestion_endpoints: o.all("--ingestion-endpoint"),
            dcr_resource_id: o.get("--dcr-resource-id"),
            workspace_resource_id: o.get("--workspace-resource-id"),
            credential: o.get("--credential"),
            json: o.has("--json"),
        }),
        ["pipeline", "validate"] => {
            Command::Pipeline(PipelineCommand::Validate(PipelineValidateArgs {
                file: o.get("--file"),
                path: o.positional(),
            }))
        }
        ["pipeline", "template"] => {
            Command::Pipeline(PipelineCommand::Template(PipelineTemplateArgs {
                id: o.get("--id"),
                template: o.positional(),
            }))
        }
        ["queue", "inspect"] => Command::Queue(QueueCommand::Inspect(database())),
        ["queue", "dead-letters"] => Command::Queue(QueueCommand::DeadLetters(DeadLettersArgs {
            database: database(),
            max: o.get("--max"),
        })),
        ["queue", "replay"] => Command::Queue(QueueCommand::Replay(ReplayArgs {
            database: database(),
            code: o.get("--code"),
            events: o.all("--event"),
            max: o.get("--max"),
        })),
        ["queue", "verify"] => Command::Queue(QueueCommand::Verify(QueueVerifyArgs {
            database: database(),
            expect_head: o.get("--expect-head"),
        })),
        ["test", "emit"] => Command::Test(TestCommand::Emit(EmitArgs {
            endpoint: o.get("--endpoint"),
        })),
        ["token", "generate"] => Command::Token(TokenCommand::Generate(TokenGenerateArgs {
            id: o.get("--id"),
        })),
        ["dcr", "generate"] => Command::Dcr(DcrCommand::Generate(DcrGenerateArgs {
            out: o.get("--out"),
            rule_name: o.get("--rule-name"),
            plan: o.get("--plan"),
            retention_days: o.get("--retention-days"),
            total_retention_days: o.get("--total-retention-days"),
        })),
        ["dcr", "diff"] => Command::Dcr(DcrCommand::Diff(DcrDiffArgs {
            rule: o.get("--rule"),
            dcr_resource_id: o.get("--dcr-resource-id"),
            table: o.get("--table"),
            workspace_resource_id: o.get("--workspace-resource-id"),
            credential: o.get("--credential"),
            arm_requested: o.has("--dcr-resource-id") || o.has("--workspace-resource-id"),
        })),
        ["keys", "generate"] => Command::Keys(KeysCommand::Generate(KeysGenerateArgs {
            out_dir: o.get("--out-dir"),
            name: o.get("--name"),
        })),
        ["pack", "build"] => Command::Pack(PackCommand::Build(PackBuildArgs {
            source: o.positional(),
            key: o.get("--key"),
            out: o.get("--out"),
        })),
        ["pack", "verify"] => Command::Pack(PackCommand::Verify(pack_file())),
        ["pack", "inspect"] => Command::Pack(PackCommand::Inspect(pack_file())),
        ["pack", "test"] => Command::Pack(PackCommand::Test(PackTestArgs {
            pack: pack_file(),
            hmac_key_file: o.get("--hmac-key-file"),
            parser: o.get("--parser"),
            report: o.get("--report"),
            report_format: o.get("--report-format"),
        })),
        ["pack", "diff"] => Command::Pack(PackCommand::Diff(PackDiffArgs {
            files: o.bowerpacks(),
            trusted_keys: o.all("--trusted-key"),
        })),
        ["evidence", "run"] => Command::Evidence(EvidenceCommand::Run(EvidenceRunArgs {
            collector_url: o.get("--collector-url"),
            workspace_id: o.get("--workspace-id"),
            workspace_resource_id: o.get("--workspace-resource-id"),
            table: o.get("--table"),
            credential: o.get("--credential"),
            client_id: o.get("--client-id"),
            timeout_minutes: o.get("--timeout-minutes"),
            signing_key: o.get("--signing-key"),
            out: o.get("--out"),
            probe_profile: o.get("--probe-profile"),
        })),
        ["evidence", "verify"] => Command::Evidence(EvidenceCommand::Verify(EvidenceVerifyArgs {
            file: o.positional(),
            trusted_keys: o.all("--trusted-key"),
        })),
        ["developer", "init"] => Command::Developer(DeveloperCommand::Init(DeveloperInitArgs {
            path: o.get("--path"),
        })),
        ["policy", "test"] => Command::Policy(PolicyCommand::Test(PolicyTestArgs {
            files: o.positionals(),
            policy_directory: o.get("--policy-directory"),
            packs: o.all("--pack"),
            trusted_keys: o.all("--trusted-key"),
            privacy_profile: o.get("--privacy-profile"),
            hmac_key_file: o.get("--hmac-key-file"),
            hmac_key_id: o.get("--hmac-key-id"),
            expect: o.get("--expect"),
        })),
        ["policy", "diff"] => Command::Policy(PolicyCommand::Diff(PolicyDiffArgs {
            // --fail-on-change takes no value; drop it so it cannot swallow the next file.
            files: Options(
                &o.0.iter()
                    .filter(|argument| *argument != "--fail-on-change")
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .positionals(),
            baseline: o.get("--baseline"),
            candidate: o.get("--candidate"),
            fail_on_change: o.has("--fail-on-change"),
            baseline_packs: o.all("--baseline-pack"),
            baseline_trusted_keys: o.all("--baseline-trusted-key"),
            baseline_privacy_profile: o.get("--baseline-privacy-profile"),
            baseline_hmac_key_file: o.get("--baseline-hmac-key-file"),
            baseline_hmac_key_id: o.get("--baseline-hmac-key-id"),
            candidate_packs: o.all("--candidate-pack"),
            candidate_trusted_keys: o.all("--candidate-trusted-key"),
            candidate_privacy_profile: o.get("--candidate-privacy-profile"),
            candidate_hmac_key_file: o.get("--candidate-hmac-key-file"),
            candidate_hmac_key_id: o.get("--candidate-hmac-key-id"),
            at: o.get("--at"),
            at_given: o.has("--at"),
            // C# `PolicyCommands.IsBundleComparison`.
            bundle: o.has("--at")
                || crate::commands::policy::BUNDLE_OPTIONS
                    .iter()
                    .any(|option| {
                        o.has(&format!("--baseline-{option}"))
                            || o.has(&format!("--candidate-{option}"))
                    }),
        })),
        ["archive", "create"] => Command::Archive(ArchiveCommand::Create(ArchiveCreateArgs {
            archive: o.get("--archive"),
            database: database(),
            collector_id: o.get("--collector-id"),
        })),
        ["archive", "verify"] => Command::Archive(ArchiveCommand::Verify(ArchiveVerifyArgs {
            archive: o.get("--archive"),
            anchor: o.get("--anchor"),
        })),
        ["archive", "replay"] => Command::Archive(ArchiveCommand::Replay(ArchiveReplayArgs {
            archive: o.get("--archive"),
            collector_url: o.get("--collector-url"),
            from: o.get("--from"),
            to: o.get("--to"),
            event_types: o.all("--event-type"),
            dry_run: o.has("--dry-run"),
        })),
        ["sources", "check"] => Command::Sources(SourcesCommand::Check(SourcesCheckArgs {
            expectations: o.get("--expectations"),
            database: database(),
        })),
        ["privacy", "validate"] => {
            Command::Privacy(PrivacyCommand::Validate(PrivacyValidateArgs {
                file: o.positional(),
                hmac_key_file: o.get("--hmac-key-file"),
                sample: o.get("--sample"),
            }))
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn options_follow_csharp_cli_options() {
        let args = strings(&["--a", "1", "x", "--a", "2", "--b", "-v", "--c"]);
        let o = Options(&args);
        assert_eq!(o.get("--a").as_deref(), Some("1"));
        assert_eq!(o.all("--a"), vec!["1", "2"]);
        assert_eq!(o.get("--b").as_deref(), Some("-v"));
        assert_eq!(o.get("--c"), None);
        assert!(o.has("--c"));
        assert_eq!(o.positional().as_deref(), Some("x"));
        assert_eq!(Options(&strings(&["--k", "v"])).positional(), None);
        assert_eq!(
            Options(&strings(&["-x", "--k", "v"]))
                .positional()
                .as_deref(),
            Some("-x")
        );
        assert_eq!(
            Options(&strings(&["--foo", "bar", "p.yaml"]))
                .positional()
                .as_deref(),
            Some("p.yaml")
        );
        assert_eq!(
            Options(&strings(&[
                "--trusted-key",
                "k.pem",
                "A.BowerPack",
                "b.bowerpack"
            ]))
            .bowerpacks(),
            vec!["A.BowerPack", "b.bowerpack"]
        );
    }

    #[test]
    fn recognises_commands_like_the_csharp_switch() {
        assert!(matches!(
            parse(&strings(&["version"])),
            Some(Command::Version)
        ));
        assert!(parse(&strings(&["version", "x"])).is_none());
        assert!(parse(&strings(&["pipeline"])).is_none());
        assert!(parse(&strings(&["-h"])).is_none());
        assert!(matches!(
            parse(&strings(&["validate", "--bogus"])),
            Some(Command::Validate(ValidateArgs {
                policy_directory: None
            }))
        ));
        let Some(Command::Doctor(doctor)) = parse(&strings(&[
            "doctor", "--json", "--pack", "a", "--pack", "b", "--json",
        ])) else {
            panic!("doctor");
        };
        assert!(doctor.json);
        assert_eq!(doctor.packs, vec!["a", "b"]);
    }

    #[test]
    fn pipeline_positionals_skip_option_values() {
        let Some(Command::Pipeline(PipelineCommand::Validate(validate))) = parse(&strings(&[
            "pipeline", "validate", "--foo", "bar", "p.yaml",
        ])) else {
            panic!("pipeline validate");
        };
        assert_eq!(validate.file, None);
        assert_eq!(validate.path.as_deref(), Some("p.yaml"));
        let Some(Command::Pipeline(PipelineCommand::Validate(validate))) =
            parse(&strings(&["pipeline", "validate", "--foo", "bar"]))
        else {
            panic!("pipeline validate");
        };
        assert_eq!(validate.path, None);
        let Some(Command::Pipeline(PipelineCommand::Template(template))) = parse(&strings(&[
            "pipeline",
            "template",
            "--format",
            "yaml",
            "aws-security",
        ])) else {
            panic!("pipeline template");
        };
        assert_eq!(template.id, None);
        assert_eq!(template.template.as_deref(), Some("aws-security"));
    }
}
