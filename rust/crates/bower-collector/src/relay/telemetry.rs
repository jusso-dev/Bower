//! Relay counters since start, for `/v1/status` (C# `RelayTelemetry`). Metadata only:
//! collector ids come from the downstreams file, never from request bodies.
//! Process-local; resets on restart.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

use bower_contracts::time::{Timestamp, serde_offset_option};
use serde::Serialize;

#[derive(Default)]
struct Downstream {
    batches: i64,
    accepted: i64,
    duplicates: i64,
    rejected: i64,
    last_batch_at: Option<Timestamp>,
}

pub struct RelayTelemetry {
    downstreams: Mutex<BTreeMap<String, Downstream>>,
    tunnels_open: AtomicI64,
    tunnels_opened: AtomicI64,
    tunnels_refused: AtomicI64,
}

impl RelayTelemetry {
    pub fn new(collector_ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            downstreams: Mutex::new(
                collector_ids
                    .into_iter()
                    .map(|id| (id, Downstream::default()))
                    .collect(),
            ),
            tunnels_open: AtomicI64::new(0),
            tunnels_opened: AtomicI64::new(0),
            tunnels_refused: AtomicI64::new(0),
        }
    }

    pub fn record_batch(
        &self,
        collector_id: &str,
        accepted: i64,
        duplicates: i64,
        rejected: i64,
        at: Timestamp,
    ) {
        let mut downstreams = self
            .downstreams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(item) = downstreams.get_mut(collector_id) {
            item.batches += 1;
            item.accepted += accepted;
            item.duplicates += duplicates;
            item.rejected += rejected;
            item.last_batch_at = Some(at);
        }
    }

    pub fn record_tunnel_opened(&self) {
        self.tunnels_open.fetch_add(1, Ordering::SeqCst);
        self.tunnels_opened.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_tunnel_closed(&self) {
        self.tunnels_open.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn record_tunnel_refused(&self) {
        self.tunnels_refused.fetch_add(1, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> RelayStatusSnapshot {
        let downstreams = self
            .downstreams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        RelayStatusSnapshot {
            downstreams: downstreams
                .iter()
                .map(|(id, item)| RelayDownstreamSnapshot {
                    collector_id: id.clone(),
                    batches: item.batches,
                    accepted: item.accepted,
                    duplicates: item.duplicates,
                    rejected: item.rejected,
                    last_batch_at: item.last_batch_at,
                })
                .collect(),
            tunnels: RelayTunnelSnapshot {
                open: self.tunnels_open.load(Ordering::SeqCst),
                opened: self.tunnels_opened.load(Ordering::SeqCst),
                refused: self.tunnels_refused.load(Ordering::SeqCst),
            },
        }
    }
}

/// The `relay` section of `/v1/status` (C# `RelayStatusSnapshot`, Web defaults).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RelayStatusSnapshot {
    pub downstreams: Vec<RelayDownstreamSnapshot>,
    pub tunnels: RelayTunnelSnapshot,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDownstreamSnapshot {
    pub collector_id: String,
    pub batches: i64,
    pub accepted: i64,
    pub duplicates: i64,
    pub rejected: i64,
    #[serde(with = "serde_offset_option")]
    pub last_batch_at: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RelayTunnelSnapshot {
    pub open: i64,
    pub opened: i64,
    pub refused: i64,
}
