//! Durable SQLite persistence for the Bower data plane.
//!
//! Port of `Bower.Persistence`. Databases are interchangeable with the C#
//! implementation: identical DDL, PRAGMAs, enum ordinals, timestamp text and
//! ledger hash chain.

mod cursor;
mod ledger;
mod pool;
mod queue;

pub use bower_contracts::time::{Clock, SystemClock};
pub use cursor::{SqliteSourceCursorStore, format_ef_date_time_offset};
pub use ledger::{GENESIS, chain_hash, genesis_hash, payload_hash};
pub use queue::{
    MAXIMUM_LEASE_COUNT, MAXIMUM_PURGE_COUNT, MINIMUM_QUEUE_BYTES, SqliteEventStore, replay_content,
};

mod identity;
pub use identity::create as event_identity;
