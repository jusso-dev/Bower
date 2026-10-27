//! Syslog source (C# `Bower.Source.Syslog`, the specification): strict RFC 5424 and
//! RFC 3164 parsing, RFC 6587 framing, flat pack-parser records and bounded TCP, TLS and
//! UDP listeners. Default deny: a message becomes an event only through a route to an
//! active signed pack parser that selects it.

pub mod config;
pub mod framing;
pub mod parser;
pub mod record;
pub mod source;

pub use config::{ListenerOptions, Route, SyslogSourceConfiguration};
pub use parser::{SyslogFormat, SyslogMessage};
pub use source::{
    ListenerStatus, SinkFailure, SourceError, SubmitOutcome, SyslogMetrics, SyslogSink,
    SyslogSource,
};
