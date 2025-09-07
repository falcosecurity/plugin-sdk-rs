use crate::base::Plugin;
use crate::parse::EventInput;
use crate::plugin::error::last_error::LastError;
use crate::plugin::parse::wrappers::ParsePluginExported;
use crate::plugin::tables::vtable::writer::LazyTableWriter;
use crate::tables::LazyTableReader;
use falco_event::events::{AnyEventPayload, RawEvent};
use falco_plugin_api::ss_plugin_event_parse_input;

#[doc(hidden)]
pub mod wrappers;

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
    pub(in crate::plugin::parse) unsafe fn try_from(
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
