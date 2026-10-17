//! `bower developer init [--path PATH]` (C# `DeveloperInit`, `DeveloperTemplates`).

use std::path::Path;

use crate::cli::DeveloperInitArgs;
use crate::output::Json;
use crate::support::{CliError, CliResult, full_path, read_text, write_text};

pub const AGENTS_SECTION: &str = "## Bower security telemetry

This repository uses Bower for structured security audit events.

When changing authentication, authorisation, administration, identity,
sensitive-data access, export, integration or security-control behaviour:

1. Determine whether change creates or modifies a security-relevant event.
2. Use strongly typed Bower SDK.
3. Emit only after authoritative action succeeds.
4. Include actor, action, target, outcome and correlation data.
5. Never include passwords, tokens, cookies, secrets or unrestricted bodies.
6. Add or update telemetry contract tests and event catalogue.
7. Run `dotnet test`, `dotnet bower analyse`, and
   `dotnet bower catalogue validate`.

Do not use ILogger as substitute for Bower security event. Do not create
free-form event types where semantic event exists. Do not duplicate events
across controller, service and persistence layers. Never weaken validation
or bypass redaction.";

pub const SECURITY_TELEMETRY: &str = "# Security telemetry

Emit semantic Bower events at authoritative transaction boundaries. Keep
actor, action, target, result and correlation context. Never include secrets,
cookies, authorization headers, unrestricted bodies or file contents.

Add `Bower.Sdk` and call `services.AddBower(...)`. Add contract tests for
every catalogue entry.";

pub const CONFIGURATION: &str = "apiVersion: bower.security/v1
kind: ApplicationConfiguration
application:
  name: replace-me
  environment: development
transport:
  type: local-collector
  endpoint: http://127.0.0.1:4319";

pub const CATALOGUE: &str = "apiVersion: bower.security/v1
kind: ApplicationTelemetryCatalogue
application:
  name: replace-me
  owner: replace-me
  environment: development
events: []";

const START: &str = "<!-- bower:security-telemetry:start -->";
const END: &str = "<!-- bower:security-telemetry:end -->";

pub fn init(args: &DeveloperInitArgs) -> CliResult {
    let root = match &args.path {
        Some(path) => full_path(path),
        None => full_path("."),
    };
    let shown = root.to_string_lossy().into_owned();
    if !root.is_dir() {
        return Err(CliError(format!(
            "Target directory does not exist: {shown}"
        )));
    }
    if !contains_csproj(&root) {
        return Err(CliError::new(
            "No .NET project detected. This release supports .NET developer init.",
        ));
    }

    let docs = root.join("docs");
    std::fs::create_dir_all(&docs).map_err(CliError::from_display)?;
    write_new(&docs.join("security-telemetry.md"), SECURITY_TELEMETRY)?;
    write_new(&root.join("bower.yaml"), CONFIGURATION)?;
    write_new(&root.join("telemetry-catalogue.yaml"), CATALOGUE)?;
    update_agents(&root.join("AGENTS.md"))?;

    let json = Json::object([
        ("initialized", Json::Bool(true)),
        ("path", Json::str(shown)),
        ("framework", Json::str("dotnet")),
        (
            "note",
            Json::str("Package references are documented but not changed automatically in 0.1.0."),
        ),
    ]);
    println!("{}", json.to_indented());
    Ok(0)
}

/// `Directory.EnumerateFiles(root, "*.csproj", SearchOption.AllDirectories).Any()`.
/// Name matching is case-insensitive on macOS and Windows like .NET's platform default.
fn contains_csproj(root: &Path) -> bool {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() || kind.is_symlink() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let matches = if cfg!(any(target_os = "macos", target_os = "windows")) {
                    name.to_ascii_lowercase().ends_with(".csproj")
                } else {
                    name.ends_with(".csproj")
                };
                if matches {
                    return true;
                }
            }
        }
    }
    false
}

fn write_new(path: &Path, content: &str) -> CliResult<()> {
    if path.exists() {
        return Ok(());
    }
    write_text(&path.to_string_lossy(), content)
}

/// Inserts or replaces the marked Bower section, keeping the rest of AGENTS.md.
pub fn updated_agents(current: Option<&str>) -> String {
    let section = format!("{START}\n{AGENTS_SECTION}\n{END}\n");
    let Some(current) = current else {
        return section;
    };
    match (current.find(START), current.find(END)) {
        (Some(start), Some(end)) if end > start => {
            let tail = current[end + END.len()..].trim_start_matches(['\r', '\n']);
            format!("{}{section}{tail}", &current[..start])
        }
        _ => format!("{}\n\n{section}", current.trim_end()),
    }
}

fn update_agents(path: &Path) -> CliResult<()> {
    let text = path.to_string_lossy().into_owned();
    let current = if path.exists() {
        Some(read_text(&text)?)
    } else {
        None
    };
    write_text(&text, &updated_agents(current.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_section_only() {
        let original = format!("# Repo\n\n{START}\nold\n{END}\n\n\nTail\n");
        let updated = updated_agents(Some(&original));
        assert!(updated.starts_with("# Repo\n\n<!-- bower:security-telemetry:start -->\n## Bower"));
        assert!(updated.ends_with(&format!("{END}\nTail\n")));
        assert!(!updated.contains("old"));
    }

    #[test]
    fn appends_after_trimmed_content() {
        let updated = updated_agents(Some("# Repo\n\n  \n"));
        assert!(updated.starts_with(&format!("# Repo\n\n{START}\n")));
    }
}
