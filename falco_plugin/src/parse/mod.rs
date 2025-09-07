//! # Event parsing support
//!
//! Plugins with event parsing capability can hook into an event stream and receive all of its events
//! sequentially. The parsing phase is the stage in the event processing loop in which
//! the Falcosecurity libraries inspect the content of the events' payload and use it to apply
//! internal state updates or implement additional logic. This phase happens before any field
//! extraction for a given event. Each event in a given stream is guaranteed to be received at most once.
//!
//! For your plugin to support event parsing, you will need to implement the [`ParsePlugin`]
//! trait and invoke the [`parse_plugin`](crate::parse_plugin) macro, for example:
//!
//! ```
//!# use std::ffi::CStr;
//! use falco_event::events::RawEvent;
//! use falco_plugin::anyhow::Error;
//! use falco_plugin::base::Plugin;
//! use falco_plugin::{parse_plugin, plugin};
//! use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
//!# use falco_plugin::tables::TablesInput;
//!
//! struct MyParsePlugin;
//!
//! impl Plugin for MyParsePlugin {
//!     // ...
//! #    const NAME: &'static CStr = c"sample-plugin-rs";
//! #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
//! #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
//! #    const CONTACT: &'static CStr = c"you@example.com";
//! #    type ConfigType = ();
//! #
//! #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
//! #        -> Result<Self, Error> {
//! #        Ok(MyParsePlugin)
//! #    }
//! }
//!
//! impl ParsePlugin for MyParsePlugin {
//!     type Event<'a> = RawEvent<'a>;
//!
//!     fn parse_event(&mut self, event: &EventInput<RawEvent>, parse_input: &ParseInput)
//!         -> Result<(), Error> {
//!         let event = event.event()?;
//!
//!         // any processing you want here, e.g. involving tables
//!
//!         Ok(())
//!     }
//! }
//!
//! plugin!(MyParsePlugin);
//! parse_plugin!(MyParsePlugin);
//! ```

use crate::base::Plugin;
use crate::parse::wrappers::ParsePluginExported;
use crate::plugin::error::last_error::LastError;
use crate::tables::LazyTableReader;
use crate::tables::LazyTableWriter;
use falco_event::events::{AnyEventPayload, RawEvent};
use falco_plugin_api::ss_plugin_event_parse_input;

#[doc(hidden)]
pub mod wrappers;

pub use crate::event::EventInput;

/// Support for event parse plugins
pub trait ParsePlugin: Plugin + ParsePluginExported {
    /// # Parsed event type
    ///
    /// Events will be parsed into this type before being passed to the plugin, so you can
    /// work directly on the deserialized form and don't need to worry about validating
    /// the events.
    ///
    /// If an event fails this conversion, an error will be returned from [`EventInput::event`],
    /// which you can propagate directly to the caller.
    ///
    /// If you don't want any specific validation/conversion to be performed, specify the type as
    /// ```
    /// type Event<'a> = falco_event::events::RawEvent<'a>;
    /// ```
    type Event<'a>: AnyEventPayload + TryFrom<&'a RawEvent<'a>>
    where
        Self: 'a;

    /// # Parse an event
    ///
    /// Receives an event from the current capture and parses its content.
    /// The plugin is guaranteed to receive an event at most once, after any
    /// operation related to the event sourcing capability, and before
    /// any operation related to the field extraction capability.
    fn parse_event(
        &mut self,
        event: &EventInput<Self::Event<'_>>,
        parse_input: &ParseInput,
    ) -> anyhow::Result<()>;
}

/// # The input to a parse plugin
///
/// It has two fields containing the vtables needed to access tables imported through
/// the [tables API](`crate::tables`).
///
/// You will pass these vtables to all methods that read or write data from tables,
/// but you won't interact with them otherwise. They're effectively tokens proving
/// you're in the right context to read/write tables.
#[derive(Debug)]
pub struct ParseInput<'t> {
    /// Accessors to read table entries
    pub reader: LazyTableReader<'t>,
    /// Accessors to modify table entries
    pub writer: LazyTableWriter<'t>,
}

impl ParseInput<'_> {
    pub(crate) unsafe fn try_from(
        value: *const ss_plugin_event_parse_input,
        last_error: LastError,
    ) -> Result<Self, anyhow::Error> {
        let input = unsafe {
            value
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Got null event parse input"))?
        };

        let reader = unsafe {
            input
                .table_reader_ext
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Got null reader vtable"))?
        };
        let writer = unsafe {
            input
                .table_writer_ext
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Got null writer vtable"))?
        };

        let reader = LazyTableReader::new(reader, last_error.clone());
        let writer = LazyTableWriter::try_from(writer, last_error)?;

        Ok(Self { reader, writer })
    }
}
