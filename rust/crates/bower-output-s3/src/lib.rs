//! Amazon S3 NDJSON object output: port of `src/Bower.Output.S3`.

pub mod layout;
pub mod options;
pub mod output;

pub use options::{S3OutputOptions, S3SettingsError};
pub use output::S3Output;
