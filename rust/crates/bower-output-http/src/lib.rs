//! Bower HTTP output (C# `Bower.Output.Http`): bounded HTTPS delivery of queued,
//! already-redacted events to Splunk HTTP Event Collector or a generic NDJSON endpoint.
//! Delivery means acceptance by the endpoint, not Sentinel delivery or indexing.

pub mod options;
pub mod output;

pub use options::{ConfigError, HttpOutputFormat, HttpOutputOptions};
pub use output::{HttpOutput, OUTPUT_ID};
