pub use event::Event;
pub use metadata::EventMetadata;
pub use payload::EventDirection;
pub use payload::EventPayload;
pub use payload::PayloadFromBytes;
pub use payload::PayloadFromBytesError;
pub use payload::PayloadToBytes;
pub use raw_event::RawEvent;
pub use to_bytes::EventToBytes;

mod event;
mod metadata;
pub(crate) mod payload;
mod raw_event;
mod to_bytes;

/// # Event types
///
/// This module is automatically generated from the Falco event schema. It provides strongly-typed
/// structs for each event type supported by Falco, as well as a [`types::AnyEvent`] enum that is capable
/// of containing an arbitrary event matching the schema.
#[allow(clippy::crate_in_macro_def)]
pub mod types;
