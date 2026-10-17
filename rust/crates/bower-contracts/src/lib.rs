//! Bower event contracts and data-plane abstractions.
//!
//! Wire format matches the C# `Bower.Contracts` assembly serialized with
//! `BowerJson.Options`: camelCase names, nulls omitted, camelCase enum strings,
//! `DateTimeOffset` round-trip text and `JavaScriptEncoder.Default` escaping.

pub mod abstractions;
pub mod element;
pub mod envelope;
pub mod json;
pub mod time;
pub mod types;

pub use abstractions::*;
pub use element::JsonElement;
pub use envelope::*;
