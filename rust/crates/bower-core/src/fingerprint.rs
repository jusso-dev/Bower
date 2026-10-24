//! Stable source identity shared with queue migration.
use bower_contracts::SecurityEventEnvelope;

pub fn create(value: &SecurityEventEnvelope) -> String {
    bower_persistence::event_identity(value)
}
