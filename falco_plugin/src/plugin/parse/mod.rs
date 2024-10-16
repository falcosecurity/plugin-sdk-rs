use crate::parse::EventInput;
use crate::plugin::base::Plugin;
use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::vtable::{TableReader, TableWriter};
use falco_event::events::types::EventType;
use falco_plugin_api::ss_plugin_event_parse_input;

#[doc(hidden)]
pub mod wrappers;

/// # Support for event parse plugins
pub trait ParsePlugin: Plugin {
    // TODO: document event_type vs anyevent vs individual event types somewhere prominent

    /// # Supported event types
    ///
    /// This list contains the event types that this plugin will receive
    /// for event parsing. Events that are not included in this list
    /// will not be received by the plugin.
    ///
    /// This is a non-functional filter that should not influence the plugin's
    /// functional behavior. Instead, this is a performance optimization
    /// with the goal of avoiding unnecessary communication between the
    /// framework and the plugin for events that are known to be not used for
    /// event parsing.
    ///
    /// If this list is empty, then:
    /// - the plugin will receive every event type if [`ParsePlugin::EVENT_SOURCES`]
    ///   is compatible with the "syscall" event source, otherwise
    /// - the plugin will only receive events of plugin type [`source::PluginEvent`](`crate::source::PluginEvent`)
    ///
    /// **Note**: some notable event types are:
    /// - [`EventType::ASYNCEVENT_E`], generated from async plugins
    /// - [`EventType::PLUGINEVENT_E`], generated from source plugins
    const EVENT_TYPES: &'static [EventType];

    /// # Supported event sources
    ///
    /// This list contains the event sources that this plugin is capable of parsing.
    ///
    /// If this list is empty, then if plugin has sourcing capability, and implements a specific
    /// event source, it will only receive events matching its event source, otherwise it will
    /// receive events from all event sources.
    ///
    /// **Note**: one notable event source is called `syscall`
    const EVENT_SOURCES: &'static [&'static str];

    /// # Parse an event
    ///
    /// Receives an event from the current capture and parses its content.
    /// The plugin is guaranteed to receive an event at most once, after any
    /// operation related the event sourcing capability, and before
    /// any operation related to the field extraction capability.
    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()>;
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
    pub reader: TableReader<'t>,
    /// Accessors to modify table entries
    pub writer: TableWriter<'t>,
}

impl<'t> ParseInput<'t> {
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

        let reader = TableReader::try_from(reader, last_error.clone())?;
        let writer = TableWriter::try_from(writer, last_error)?;

        Ok(Self { reader, writer })
    }
}
