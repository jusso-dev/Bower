//! Console logging: single line, UTC timestamps (C# `AddSimpleConsole`).
//!
//! Level precedence: `RUST_LOG`, then ASP.NET configuration `Logging:LogLevel:Default`
//! from `Logging__LogLevel__Default`, `appsettings.{Environment}.json` and
//! `appsettings.json` in the working directory, then `Information`. Framework
//! logs (hyper) stay at warning, as the C# host filters `Microsoft.AspNetCore`.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

/// Maps a .NET `LogLevel` name to a tracing directive.
fn dotnet_level(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "trace" => Some("trace"),
        "debug" => Some("debug"),
        "information" => Some("info"),
        "warning" => Some("warn"),
        "error" | "critical" => Some("error"),
        "none" => Some("off"),
        _ => None,
    }
}

fn appsettings_level(file: &str) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
    let value: serde_json::Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    // ASP.NET configuration keys are case-insensitive.
    let find = |value: &serde_json::Value, key: &str| -> Option<serde_json::Value> {
        value
            .as_object()?
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.clone())
    };
    let logging = find(&value, "Logging")?;
    let levels = find(&logging, "LogLevel")?;
    find(&levels, "Default")?.as_str().map(str::to_string)
}

pub fn configured_default_level(read: impl Fn(&str) -> Option<String>) -> &'static str {
    let environment = read("DOTNET_ENVIRONMENT")
        .or_else(|| read("ASPNETCORE_ENVIRONMENT"))
        .unwrap_or_else(|| "Production".into());
    read("Logging__LogLevel__Default")
        .or_else(|| appsettings_level(&format!("appsettings.{environment}.json")))
        .or_else(|| appsettings_level("appsettings.json"))
        .and_then(|name| dotnet_level(&name))
        .unwrap_or("info")
}

pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = configured_default_level(|name| std::env::var(name).ok());
        EnvFilter::new(format!(
            "{level},hyper=warn,hyper_util=warn,reqwest=warn,h2=warn,rustls=warn"
        ))
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(std::io::stdout().is_terminal())
        .with_writer(std::io::stdout)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_aspnet_levels() {
        assert_eq!(
            configured_default_level(
                |name| (name == "Logging__LogLevel__Default").then(|| "Warning".into())
            ),
            "warn"
        );
        assert_eq!(dotnet_level("None"), Some("off"));
        assert_eq!(dotnet_level("bogus"), None);
    }
}
