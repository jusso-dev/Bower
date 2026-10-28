//! Downstream collectors a relay accepts (C# `RelayDownstreams`, BOWER_RELAY_DOWNSTREAMS_FILE).
//! Each entry binds one collector id to the SHA-256 pin of its client certificate. The
//! mutual TLS handshake refuses any other certificate, and a downstream can only submit
//! events and open tunnels as the collector id its pin names. Loaded once at start-up.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use bower_contracts::time::Timestamp;

use super::certificates;
use super::protocol::{self, RawObject};
use crate::error::HostError;

pub const MAXIMUM_ENTRIES: usize = 1024;
pub const MAXIMUM_FILE_BYTES: u64 = 256 * 1024;
const INVALID: &str = "BOWER_RELAY_DOWNSTREAMS_FILE must be a JSON object with a downstreams array of 1 to 1024 \
     {collectorId, certificateSha256} entries, each pin a distinct SHA-256 hex value.";

#[derive(Debug)]
pub struct RelayDownstreams {
    collector_by_pin: HashMap<String, String>,
}

fn invalid() -> HostError {
    HostError::new("InvalidOperationException", INVALID)
}

impl RelayDownstreams {
    pub fn load(path: &Path) -> Result<Self, HostError> {
        let metadata = std::fs::metadata(path).map_err(|_| invalid())?;
        if !metadata.is_file() || metadata.len() > MAXIMUM_FILE_BYTES {
            return Err(invalid());
        }
        Self::parse(&std::fs::read(path).map_err(|_| invalid())?)
    }

    pub fn parse(json: &[u8]) -> Result<Self, HostError> {
        if json.len() as u64 > MAXIMUM_FILE_BYTES || !protocol::within_depth(json, 8) {
            return Err(invalid());
        }
        let root: Box<serde_json::value::RawValue> =
            serde_json::from_slice(json).map_err(|_| invalid())?;
        let root = protocol::as_object(&root).ok_or_else(invalid)?;
        let list = root
            .single("downstreams")
            .and_then(protocol::as_array)
            .filter(|list| (1..=MAXIMUM_ENTRIES).contains(&list.len()))
            .ok_or_else(invalid)?;
        let mut collector_by_pin = HashMap::new();
        for entry in &list {
            let entry: RawObject = protocol::as_object(entry).ok_or_else(invalid)?;
            let id = entry
                .single("collectorId")
                .and_then(protocol::as_string)
                .filter(|id| protocol::is_valid_identifier(id))
                .ok_or_else(invalid)?;
            let pin = entry
                .single("certificateSha256")
                .and_then(protocol::as_string)
                .and_then(|pin| normalise_pin(&pin))
                .ok_or_else(invalid)?;
            if collector_by_pin.insert(pin, id).is_some() {
                return Err(invalid());
            }
        }
        Ok(Self { collector_by_pin })
    }

    /// Distinct collector ids, ordinal order.
    pub fn collector_ids(&self) -> Vec<String> {
        self.collector_by_pin
            .values()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The collector id a presented certificate (DER) may act as, or `None`.
    pub fn resolve(&self, certificate: &[u8], now: Timestamp) -> Option<String> {
        if !certificates::is_usable_client_certificate(certificate, now) {
            return None;
        }
        self.collector_by_pin
            .get(&certificates::pin(certificate))
            .cloned()
    }
}

/// 64 hex digits, case-insensitive, optionally colon separated (openssl output).
pub fn normalise_pin(value: &str) -> Option<String> {
    let compact = value.replace(':', "").to_lowercase();
    (compact.len() == 64 && compact.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(compact)
}
