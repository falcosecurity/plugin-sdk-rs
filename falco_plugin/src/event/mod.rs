//! # Event-related types
//!
//! This module reexports the whole of [`falco_event`] (except the macros), as well as exports
//! the event types defined by this crate (the minimal subset of the full Falco schema)

mod async_event;
mod event_input;
mod json;
mod plugin_event;

pub use async_event::AsyncEvent;
pub use event_input::EventInput;
use falco_event::fields::{FromBytes, ToBytes};
pub use falco_event::{events, fields};
pub use json::JsonPayload;
pub use plugin_event::PluginEvent;
use std::fmt::Debug;

/// Provide an event source name for an event type
///
/// This is required to use that type as an event payload
pub trait EventSource {
    /// Source name
    ///
    /// `syscall` for system call events, an arbitrary string (matching the one in the source plugin
    /// implementation) for custom plugin/async events
    const SOURCE: Option<&'static str>;
}

impl EventSource for &[u8] {
    const SOURCE: Option<&'static str> = None;
}

/// A generic enum for custom plugin/async event payloads
///
/// Type parameters:
/// - `P` specifies the payload of the `Plugin` variant
/// - `A` specifies the payload of the `Async` variant
#[derive(falco_event::AnyEvent)]
#[allow(missing_docs)]
pub enum AnyPluginEvent<'a, P, A>
where
    for<'b> P: EventSource + ToBytes + FromBytes<'b> + Debug,
    A: EventSource + ToBytes + FromBytes<'a> + Debug,
{
    Plugin(PluginEvent<P>),
    Async(AsyncEvent<'a, A>),
}
