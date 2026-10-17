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
//! Known differences from C# (all fail closed):
//! - Structures C# turns into a `NullReferenceException` (missing `metadata`,
//!   `match`, `decision`, null `eventTypes`) or that load in C# but throw on
//!   every evaluation (null `requirements`, null requirement lists, null
//!   `eventCategories` or category items) are rejected as invalid data.
//! - `reviewDate` accepts only `yyyy-M-d` / `yyyy/M/d`; C# uses
//!   current-culture `DateOnly.Parse`, which also accepts e.g. `Jan 5, 2027`.
//! - A mapping given for an integer, boolean or date is rejected; C# reads
//!   `{}` as the default value and reports the first key otherwise.
//! - YAML syntax errors report the libyaml message and line, not YamlDotNet's.

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
pub use field::has_value;
pub use loader::{
    MAXIMUM_POLICY_BYTES, PolicyError, SUPPORTED_API_VERSION, SUPPORTED_KIND, load_directory,
    load_file, load_yaml, try_parse_action,
};
pub use model::{
    LoadedPolicy, PolicyAction, PolicyMatch, PolicyMetadata, PolicyRequirements, PolicyRouting,
    TelemetryPolicy,
};
