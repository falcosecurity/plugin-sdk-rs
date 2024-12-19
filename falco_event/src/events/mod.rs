pub use event::Event;
pub use metadata::EventMetadata;
pub use payload::EventDirection;
pub use payload::EventPayload;
pub use payload::PayloadFromBytes;
pub use payload::PayloadToBytes;
pub use raw_event::RawEvent;
pub use to_bytes::EventToBytes;

mod event;
mod metadata;
pub(crate) mod payload;
mod raw_event;
#[cfg(all(test, feature = "serde"))]
mod serde_tests;
mod to_bytes;

/// # Event types
///
/// This module is automatically generated from the Falco event schema. It provides strongly-typed
/// structs for each event type supported by Falco, as well as a [`types::AnyEvent`] enum that is capable
/// of containing an arbitrary event matching the schema.
///
/// ## Borrowed and owned types
///
/// When you load an event from a byte buffer via [`crate::events::RawEvent::load`]
/// or [`crate::events::RawEvent::load_any`], the resulting type borrows the content of any
/// variable-length fields (paths, byte buffers etc.) from the raw byte buffer as that is more
/// efficient than copying everything.
///
/// However, borrowed types do not play nicely with [`serde`], as you cannot always provide a slice
/// of the serialized data that is suitable for the borrow. Consider deserializing `"foo"` vs `"foo\nbar"`
/// from JSON: the second string cannot be used to back a borrowed `&str` since the `\n` sequence has to be
/// replaced with a literal newline character and the resulting string has to be owned by somebody before
/// it can be borrowed.
///
/// So, to support deserialization from other types, the SDK provides a parallel set of owned event types
/// in the [`types::owned`] module. Where possible, these are simply reexports of the borrowed types, otherwise
/// a new type is introduced, using the [owned field types](`crate::fields::types::owned`).
///
/// The fields of owned events are the same as for borrowed events, except they use the types from
/// the [`crate::fields::types::owned`] module for all fields.
///
/// If you only concern yourself with the standard binary event format, you can safely ignore the existence
/// of owned event types. However, if you want to load events from a different format, you will probably
/// want to use them.
///
/// The supported format conversions on owned vs borrowed event types are summarized as follows:
///
/// | Operation                                                 | Borrowed events | Owned events |
/// |-----------------------------------------------------------|-----------------|--------------|
/// | Loading from a [RawEvent](`crate::events::RawEvent`)      | supported       | ^1           |
/// | [writing to a byte buffer](`crate::events::EventToBytes`) | supported       | supported    |
/// | [arbitrary serialization](`serde::Serialize`) ^2          | supported       | supported    |
/// | [arbitrary deserialization](`serde::Deserialize`) ^2      |                 | supported    |
///
/// **Footnotes**:
///
/// 1. Loading an owned event from a raw event is technically possible but has no benefits over
///    loading a borrowed event and incurs extra allocations and copies, so to avoid the confusion
///    it's explicitly not supported.
///
/// 2. Arbitrary serialization and deserialization with [`serde`] is only supported when
///    the `serde` feature of the crate is enabled.
pub mod types;
