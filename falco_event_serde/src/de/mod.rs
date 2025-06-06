//! Deserialization support
//!
//! This module provides the deserialization support for Falco events in the form of an [`Event`]
//! struct. The result of deserialization is not an event, but a vector of bytes that can be
//! deserialized into an event using the `falco_event` crate.
//!
//! # Example
//! ```
//! use falco_event::events::types::PPME_GENERIC_E;
//! use falco_event::fields::types::PT_SYSCALLID;
//!
//! // Use a JSON document as an example
//! let json = r#"{
//!     "ts": 1700000000,
//!     "tid": 12345,
//!     "GENERIC_E": {
//!         "id": 1,
//!         "native_id": 1001
//!     }
//! }"#;
//!
//! // Deserialize the JSON into a deserialized Falco event
//! // This is not directly usable as an event, we have to convert and parse it first.
//! let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
//!
//! // Convert the event to a byte vector
//! let bytes = event.to_vec();
//!
//! // Now we can load the event using the falco_event crate
//! let event = falco_event::events::RawEvent::from(&bytes).unwrap();
//! let event = event.load::<PPME_GENERIC_E>().unwrap();
//!
//! // Check the deserialized parameters
//! assert_eq!(event.params.id, Some(PT_SYSCALLID(1)));
//! assert_eq!(event.params.native_id, Some(1001));
//! ```
mod events;
mod payload;
mod repr;

pub use events::Event;
