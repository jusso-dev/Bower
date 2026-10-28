//! Relay (aggregator) mode for segmented and DMZ networks (issue #110; C#
//! `Bower.Collector.Relay` and `Bower.Forwarding.RelayOutput`). A downstream collector
//! (`BOWER_OUTPUT=relay`) posts already redacted, decided envelopes to a relay over mutual
//! TLS; the relay keeps them in its own durable queue and delivers them. Management traffic
//! can cross the relay in a byte tunnel whose TLS runs end to end.

pub mod certificates;
pub mod client;
pub mod downstreams;
pub mod intake;
pub mod listener;
pub mod output;
pub mod protocol;
pub mod telemetry;
