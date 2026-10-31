//! BOWER_SYSLOG_CONFIG (C# `SyslogSourceConfigurationLoader`): same shape, defaults,
//! bounds and messages.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use serde::Deserialize;

use crate::parser::SyslogMessage;

pub const MAXIMUM_LISTENERS: usize = 16;
pub const MAXIMUM_SENDERS: usize = 64;
pub const MAXIMUM_ROUTES: usize = 64;
const MAXIMUM_BYTES: u64 = 262_144;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("Syslog source configuration file does not exist.")]
    FileNotFound,
    #[error("{0}")]
    InvalidData(String),
    #[error("Syslog source configuration file could not be read: {0}")]
    Io(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyslogSourceConfiguration {
    pub api_version: String,
    pub kind: String,
    pub listeners: Vec<ListenerOptions>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerOptions {
    pub id: String,
    /// `tcp`, `tls` or `udp`.
    pub protocol: String,
    /// 0 lets the operating system choose (tests and diagnostics).
    pub port: i64,
    pub allowed_senders: Vec<String>,
    /// First match wins. A message no route matches is dropped (default deny).
    pub routes: Vec<Option<Route>>,
    #[serde(default = "default_address")]
    pub address: String,
    #[serde(default = "default_maximum_message_bytes")]
    pub maximum_message_bytes: i64,
    #[serde(default = "default_maximum_connections")]
    pub maximum_connections: i64,
    #[serde(default = "default_idle_timeout_seconds")]
    pub idle_timeout_seconds: i64,
    #[serde(default)]
    pub tls: Option<TlsOptions>,
    #[serde(default)]
    pub allow_insecure_non_loopback: bool,
    #[serde(skip)]
    senders: Vec<Network>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsOptions {
    pub certificate_file: String,
    pub private_key_file: String,
    #[serde(default)]
    pub client_certificate_authority_file: Option<String>,
    /// PEM or DER revocation lists from the client CAs; requires
    /// `client_certificate_authority_file` (C# `ClientCertificateRevocationListFile`).
    #[serde(default)]
    pub client_certificate_revocation_list_file: Option<String>,
}

/// Maps matching messages to one active parser of a loaded signed pack. Hostname and
/// app-name are claimed by the sender; `allowed_senders` pins the route to the addresses
/// that may claim them.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub pack: String,
    pub parser: i64,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub allowed_senders: Option<Vec<String>>,
    #[serde(skip)]
    senders: Vec<Network>,
}

fn default_address() -> String {
    "127.0.0.1".into()
}
fn default_maximum_message_bytes() -> i64 {
    65_536
}
fn default_maximum_connections() -> i64 {
    64
}
fn default_idle_timeout_seconds() -> i64 {
    60
}

impl ListenerOptions {
    /// Sender allow-list check; IPv4-mapped IPv6 senders match IPv4 ranges.
    pub fn allows(&self, sender: IpAddr) -> bool {
        let address = normalise(sender);
        self.senders.iter().any(|network| network.contains(address))
    }

    pub fn route(&self, message: &SyslogMessage, sender: IpAddr) -> Option<&Route> {
        let address = normalise(sender);
        self.routes.iter().flatten().find(|route| {
            route
                .hostname
                .as_ref()
                .is_none_or(|hostname| message.hostname.as_ref() == Some(hostname))
                && route
                    .app_name
                    .as_ref()
                    .is_none_or(|app| message.app_name.as_ref() == Some(app))
                && (route.allowed_senders.is_none()
                    || route
                        .senders
                        .iter()
                        .any(|network| network.contains(address)))
        })
    }

    pub fn ip_address(&self) -> IpAddr {
        parse_address(&self.address).unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}

/// Sender identity (C# `SyslogSource.NormaliseSender`): IPv4-mapped IPv6 becomes IPv4.
/// `IpAddr` never carries an IPv6 interface scope, so `fe80::1%2` is already `fe80::1`.
pub fn normalise(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        v4 => v4,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Network {
    network: IpAddr,
    prefix: u32,
}

impl Network {
    fn contains(&self, address: IpAddr) -> bool {
        let (left, right): (Vec<u8>, Vec<u8>) = match (self.network, address) {
            (IpAddr::V4(left), IpAddr::V4(right)) => {
                (left.octets().to_vec(), right.octets().to_vec())
            }
            (IpAddr::V6(left), IpAddr::V6(right)) => {
                (left.octets().to_vec(), right.octets().to_vec())
            }
            _ => return false,
        };
        (0..self.prefix as usize).all(|bit| {
            let mask = 0x80u8 >> (bit % 8);
            left[bit / 8] & mask == right[bit / 8] & mask
        })
    }

    /// Address or address/prefix in canonical form; host bits must be zero.
    fn parse(text: &str) -> Option<Self> {
        let (address_text, prefix_text) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address = parse_address(address_text)?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            None => maximum,
            Some(prefix) => {
                if !(1..=3).contains(&prefix.len())
                    || !prefix.bytes().all(|byte| byte.is_ascii_digit())
                    || (prefix.len() > 1 && prefix.starts_with('0'))
                {
                    return None;
                }
                let value: u32 = prefix.parse().ok()?;
                if value > maximum {
                    return None;
                }
                value
            }
        };
        let bytes = match address {
            IpAddr::V4(value) => value.octets().to_vec(),
            IpAddr::V6(value) => value.octets().to_vec(),
        };
        let host_bits_clear =
            (prefix..maximum).all(|bit| bytes[bit as usize / 8] & (0x80 >> (bit % 8)) == 0);
        host_bits_clear.then_some(Self {
            network: address,
            prefix,
        })
    }
}

/// Canonical IP text only (no shorthand IPv4, no IPv6 scope).
pub fn parse_address(text: &str) -> Option<IpAddr> {
    // Hex digits, ':' and '.' only: no brackets, ports, scopes or whitespace.
    if text.is_empty()
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
    {
        return None;
    }
    text.parse().ok()
}

pub fn load_file(path: impl AsRef<Path>) -> Result<SyslogSourceConfiguration, ConfigError> {
    let path = path.as_ref();
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Err(ConfigError::FileNotFound),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::FileNotFound);
        }
        Err(error) => return Err(ConfigError::Io(format!("{:?}", error.kind()))),
    };
    if metadata.len() > MAXIMUM_BYTES {
        return Err(ConfigError::InvalidData(
            "Syslog source configuration file exceeds 256 KiB.".into(),
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| ConfigError::Io(format!("{:?}", error.kind())))?;
    parse(&text)
}

pub fn parse(json: &str) -> Result<SyslogSourceConfiguration, ConfigError> {
    let mut configuration: SyslogSourceConfiguration =
        serde_json::from_str(json).map_err(|error| {
            ConfigError::InvalidData(format!("Syslog source configuration is invalid: {error}"))
        })?;
    if configuration.api_version != "bower.security/v1" || configuration.kind != "SyslogSource" {
        return Err(invalid_data(
            "Syslog source configuration needs apiVersion bower.security/v1 and kind SyslogSource.",
        ));
    }
    if !(1..=MAXIMUM_LISTENERS).contains(&configuration.listeners.len()) {
        return Err(invalid_data(format!(
            "Syslog source configuration must list 1–{MAXIMUM_LISTENERS} listeners."
        )));
    }
    let mut ids = HashSet::new();
    for listener in &mut configuration.listeners {
        validate(listener)?;
        if !ids.insert(listener.id.clone()) {
            return Err(invalid_data(format!(
                "Syslog listener {} is listed more than once.",
                listener.id
            )));
        }
    }
    Ok(configuration)
}

fn validate(listener: &mut ListenerOptions) -> Result<(), ConfigError> {
    if !is_listener_id(&listener.id) {
        return Err(invalid_data(
            "Syslog listener id must be 1–63 lowercase letters, digits or hyphens and start with a letter or digit.",
        ));
    }
    let id = listener.id.clone();
    let fail = |message: String| invalid_data(format!("Syslog listener {id}: {message}"));
    if !matches!(listener.protocol.as_str(), "tcp" | "tls" | "udp") {
        return Err(fail("protocol must be tcp, tls or udp.".into()));
    }
    let Some(address) = parse_address(&listener.address) else {
        return Err(fail("address must be an IP address.".into()));
    };
    if !(0..=65_535).contains(&listener.port) {
        return Err(fail("port must be between 0 and 65535.".into()));
    }
    if !normalise(address).is_loopback()
        && listener.protocol != "tls"
        && !listener.allow_insecure_non_loopback
    {
        return Err(fail(
            "a non-loopback address requires protocol tls; set allowInsecureNonLoopback only on an isolated network."
                .into(),
        ));
    }
    let tls_valid = match &listener.tls {
        Some(tls) => {
            listener.protocol == "tls"
                && !tls.certificate_file.trim().is_empty()
                && !tls.private_key_file.trim().is_empty()
        }
        None => listener.protocol != "tls",
    };
    if !tls_valid {
        return Err(fail(
            "tls settings are required for protocol tls and not allowed otherwise.".into(),
        ));
    }
    if let Some(tls) = &listener.tls
        && let Some(list) = &tls.client_certificate_revocation_list_file
        && (list.trim().is_empty() || tls.client_certificate_authority_file.is_none())
    {
        return Err(fail(
            "tls.clientCertificateRevocationListFile requires tls.clientCertificateAuthorityFile."
                .into(),
        ));
    }
    if !(1..=MAXIMUM_SENDERS).contains(&listener.allowed_senders.len()) {
        return Err(fail(format!(
            "allowedSenders must list 1–{MAXIMUM_SENDERS} addresses or CIDR ranges."
        )));
    }
    let mut senders = Vec::new();
    for sender in &listener.allowed_senders {
        senders.push(Network::parse(sender).ok_or_else(|| {
            fail(format!(
                "allowed sender '{sender}' is not a valid address or CIDR range."
            ))
        })?);
    }
    if !(480..=65_536).contains(&listener.maximum_message_bytes) {
        return Err(fail(
            "maximumMessageBytes must be between 480 and 65536.".into(),
        ));
    }
    if !(1..=1_024).contains(&listener.maximum_connections) {
        return Err(fail(
            "maximumConnections must be between 1 and 1024.".into(),
        ));
    }
    if !(1..=3_600).contains(&listener.idle_timeout_seconds) {
        return Err(fail(
            "idleTimeoutSeconds must be between 1 and 3600.".into(),
        ));
    }
    if !(1..=MAXIMUM_ROUTES).contains(&listener.routes.len()) {
        return Err(fail(format!(
            "routes must list 1–{MAXIMUM_ROUTES} entries."
        )));
    }
    for route in &mut listener.routes {
        let Some(route) = route
            .as_mut()
            .filter(|route| !route.pack.trim().is_empty() && route.parser >= 0)
        else {
            return Err(fail(
                "each route needs a pack id and a parser index of 0 or more.".into(),
            ));
        };
        if route
            .hostname
            .as_ref()
            .is_some_and(|value| !is_printable(value, 255))
            || route
                .app_name
                .as_ref()
                .is_some_and(|value| !is_printable(value, 48))
        {
            return Err(fail(
                "route hostname and appName must be 1–255 and 1–48 printable ASCII characters."
                    .into(),
            ));
        }
        if let Some(allowed) = &route.allowed_senders {
            if !(1..=MAXIMUM_SENDERS).contains(&allowed.len()) {
                return Err(fail(format!(
                    "route allowedSenders must list 1–{MAXIMUM_SENDERS} addresses or CIDR ranges."
                )));
            }
            let mut networks = Vec::new();
            for sender in allowed {
                networks.push(Network::parse(sender).ok_or_else(|| {
                    fail(format!(
                        "allowed sender '{sender}' is not a valid address or CIDR range."
                    ))
                })?);
            }
            route.senders = networks;
        }
    }
    listener.senders = senders;
    Ok(())
}

fn is_listener_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn is_printable(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len()) && value.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
}

fn invalid_data(message: impl Into<String>) -> ConfigError {
    ConfigError::InvalidData(message.into())
}
