//! File tail source (C# `Bower.Source.File`, the specification): a short list of
//! operator-selected files, path guards, a bounded plain-text tail with rename and
//! copytruncate rotation, flat pack-parser records and durable cursors. Default deny: a
//! line becomes an event only through its route to an active signed pack parser that
//! selects it.

pub mod config;
pub mod handle;
pub mod paths;
pub mod reader;
pub mod record;
pub mod source;

pub use config::{FileTailSourceConfiguration, InputOptions, Route};
pub use paths::PathState;
pub use reader::{Batch, Cursor, Line, ReadError, ReaderOptions, RotationState};
pub use source::{
    FileTailError, FileTailMetrics, FileTailSink, FileTailSource, InputStatus, PollResult,
    SinkFailure, SubmitOutcome,
};
