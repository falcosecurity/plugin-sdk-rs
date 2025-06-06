//! Serialization support
//!
//! This module provides serialization support for Falco events in the form of an [`Event`]
//! wrapper struct. A reference to any [`falco_event::events::Event`] can be converted into this
//! struct, which implements [`serde::Serialize`].
mod field;
mod payload;

use serde::Serialize;

/// A wrapper struct for Falco events that implements `Serialize`.
///
/// # Example
/// ```ignore
/// // Take an arbitrary Falco event
/// let event: falco_event::events::Event<falco_event::events::types::AnyEvent> = todo!();
///
/// // Wrap a reference to it for serialization
/// let serializable_event = falco_event_serde::ser::Event::from(&event);
///
/// // Serialize the event to a JSON string
/// let json = serde_json::to_string(&serializable_event).unwrap();
/// ```
#[derive(Serialize)]
pub struct Event<'a, 'ser> {
    ts: u64,
    tid: i64,
    #[serde(flatten)]
    event: payload::AnyEvent<'a, 'ser>,
}

impl<'a, 'ser, T> From<&'ser falco_event::events::Event<T>> for Event<'a, 'ser>
where
    payload::AnyEvent<'a, 'ser>: From<&'ser T>,
{
    fn from(value: &'ser falco_event::events::Event<T>) -> Self {
        Self {
            ts: value.metadata.ts,
            tid: value.metadata.tid,
            event: payload::AnyEvent::from(&value.params),
        }
    }
}
