//! Deterministic, explainable event selection: port of `Bower.PolicyEngine`.
//!
//! Policies load strictly from YAML (unknown keys, numeric actions and
//! category-only matches are rejected) and are hashed as
//! `sha256:<hex>` over the bytes of C# `JsonSerializer.Serialize(policy)`
//! (default options: PascalCase names in declaration order, nulls written,
//! `JavaScriptEncoder.Default` escaping, `DateOnly` as `yyyy-MM-dd`), so hashes
//! match the C# collector byte for byte. Unknown event types are default-deny
//! (`BWR-POL-DEFAULT-DENY`). Configuration never executes code.
//!
//! Integers, booleans and `reviewDate` accept only canonical text
//! (`-?(0|[1-9][0-9]*)`, `true`/`false`, `yyyy-MM-dd`); missing or null
//! sections, lists and list items, and blank field paths, fail the load.
//!
//! Known differences from C# (both reject the policy; only the message differs):
//! - YAML syntax errors report the libyaml message and line, not YamlDotNet's.
//! - A scalar written on the line after a section or list key is reported at
//!   the scalar's line; C# reports the key's line.

mod evaluator;
mod field;
mod loader;
mod model;
mod scalar;
mod yaml;

pub use evaluator::{
    DEFAULT_DENY_POLICY_HASH, DEFAULT_DENY_POLICY_ID, DEFAULT_DENY_POLICY_VERSION,
    DeterministicPolicyEvaluator,
};
pub use field::{get_suppression_key_value, has_value, is_suppression_key};
pub use loader::{
    MAXIMUM_POLICY_BYTES, MAXIMUM_SUPPRESSION_KEY_FIELDS, PolicyError, SUPPORTED_API_VERSION,
    SUPPORTED_KIND, load_directory, load_file, load_yaml, try_parse_action, validate_set,
};
pub use model::{
    LoadedPolicy, PolicyAction, PolicyMatch, PolicyMetadata, PolicyRequirements, PolicyRouting,
    PolicySuppression, TelemetryPolicy,
};
