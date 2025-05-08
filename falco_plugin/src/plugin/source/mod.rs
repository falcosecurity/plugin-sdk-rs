use crate::plugin::base::Plugin;
use crate::plugin::source::wrappers::SourcePluginExported;
use crate::source::{EventBatch, EventInput};
use falco_event::events::types::PPME_PLUGINEVENT_E as PluginEvent;
use falco_event::events::Event;
use falco_event::events::EventMetadata;
use std::ffi::{CStr, CString};

pub mod event_batch;
pub mod open_params;
#[doc(hidden)]
pub mod wrappers;

/// Support for event sourcing plugins
pub trait SourcePlugin: Plugin + SourcePluginExported {
    /// # Instance type
    ///
    /// Each source plugin defines an instance type. The instance is the object responsible
    /// for actual generation of events. The plugin type mostly serves as a way to create
    /// and destroy instances.
    ///
    /// **Note**: while there may be multiple instances for a particular plugin, there will be
    /// at most one at any given time.
    type Instance: SourcePluginInstance<Plugin = Self>;

    /// # Event source name
    ///
    /// This string describes the event source. One notable event source name is `syscall`,
    /// for plugins collecting syscall information.
    ///
    /// If the plugin defines both `EVENT_SOURCE` (as a non-empty string) and `PLUGIN_ID`
    /// (as a non-zero value), it will only be allowed to emit events of type [`PluginEvent`]
    /// with the `plugin_id` field matching `PLUGIN_ID` in the definition of this trait.
    ///
    /// This constant must be a non-empty string if `PLUGIN_ID` is set.
    const EVENT_SOURCE: &'static CStr;

    /// # Plugin ID
    ///
    /// This is the unique ID of the plugin.
    ///
    /// If the plugin defines both `EVENT_SOURCE` (as a non-empty string) and `PLUGIN_ID`
    /// (as a non-zero value), it will only be allowed to emit events of type [`PluginEvent`]
    /// with the `plugin_id` field matching `PLUGIN_ID` in the definition of this trait.
    ///
    /// > EVERY PLUGIN WITH EVENT SOURCING CAPABILITY IMPLEMENTING A SPECIFIC EVENT SOURCE MUST
    /// > OBTAIN AN OFFICIAL ID FROM THE FALCOSECURITY ORGANIZATION, OTHERWISE IT WON'T PROPERLY
    /// > COEXIST WITH OTHER PLUGINS.
    const PLUGIN_ID: u32;

    /// # List sample open parameters
    ///
    /// Return a list of suggested open parameters supported by this plugin.
    /// Any of the values in the returned list are valid parameters for open().
    ///
    /// The default implementation returns an empty string, but you can use
    /// [`crate::source::serialize_open_params`] and [`crate::source::OpenParam`] to build
    /// a description of what the [`SourcePlugin::open`] method expects.
    ///
    /// **Note**: as of API version 3.4.0, this appears unused.
    fn list_open_params(&mut self) -> Result<&CStr, anyhow::Error> {
        Ok(c"")
    }

    /// # Open a capture instance
    ///
    /// This method receives the `open` parameter from Falco configuration and returns
    /// a new instance of the source plugin.
    fn open(&mut self, params: Option<&str>) -> Result<Self::Instance, anyhow::Error>;

    /// # Close a capture instance
    ///
    /// The default implementation does nothing, leaving all cleanup to the instance type's
    /// [`Drop`] implementation, if any.
    fn close(&mut self, _instance: &mut Self::Instance) {}

    /// # Render an event to string
    ///
    /// This string will be available as `%evt.plugininfo` in Falco rules. You may consider
    /// using the helpers from [`crate::strings`] to build the resulting CString.
    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, anyhow::Error>;
}

/// Information about capture progress
#[derive(Debug)]
pub struct ProgressInfo<'a> {
    /// Progress percentage (0.0-100.0)
    pub value: f64,
    /// Optional detailed message about the progress
    pub detail: Option<&'a CStr>,
}

pub(crate) struct SourcePluginInstanceWrapper<I: SourcePluginInstance> {
    pub(crate) instance: I,
    pub(crate) batch: bumpalo::Bump,
}

/// # An open instance of a source plugin
pub trait SourcePluginInstance {
    /// # The [`SourcePlugin`] this instance belongs to.
    ///
    /// Source plugin and instance types must correspond 1:1 to each other.
    type Plugin: SourcePlugin<Instance = Self>;

    /// # Fill the next batch of events
    ///
    /// This is the most important method for the source plugin implementation. It is responsible
    /// for actually generating the events for the main event loop.
    ///
    /// For performance, events are returned in batches. Of course, it's entirely valid to have
    /// just a single event in a batch.
    ///
    /// ## Returning one or more events
    ///
    /// For each event that is ready, pass it to `batch.add()` to add it to the current batch
    /// to be returned.
    ///
    /// ```ignore
    /// fn next_batch(
    ///     &mut self,
    ///     plugin: &mut Self::Plugin,
    ///     batch: &mut EventBatch,
    /// ) -> Result<(), anyhow::Error> {
    ///     let mut event = Vec::new();
    ///     // ...
    ///     let event = Self::plugin_event(&event);
    ///     batch.add(event)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// ## Returning no events, temporarily
    ///
    /// If there are no events to return at the moment but there might be later, you should
    /// return [`FailureReason::Timeout`](`crate::FailureReason::Timeout`) as the error. The plugin framework will retry the call
    /// to `next_batch` later.
    ///
    /// ```ignore
    /// fn next_batch(
    ///     &mut self,
    ///     plugin: &mut Self::Plugin,
    ///     batch: &mut EventBatch,
    /// ) -> Result<(), anyhow::Error> {
    ///     std::thread::sleep(Duration::from_millis(100));
    ///     Err(anyhow::anyhow!("no events right now").context(FailureReason::Timeout))
    /// }
    /// ```
    ///
    /// ## Returning no events, permanently
    ///
    /// If there will be no more events coming from this instance, you should return\
    /// [`FailureReason::Eof`](`crate::FailureReason::Eof`) as the error. The plugin framework will end the capture and shut down
    /// gracefully.
    ///
    /// ```ignore
    /// fn next_batch(
    ///     &mut self,
    ///     plugin: &mut Self::Plugin,
    ///     batch: &mut EventBatch,
    /// ) -> Result<(), anyhow::Error> {
    ///     Err(anyhow::anyhow!("no more events").context(FailureReason::Eof))
    /// }
    /// ```
    ///
    /// ## Timing considerations
    ///
    /// This method is effectively called in a loop by Falco and there's a delicate balance of
    /// how much time to spend here waiting for events. On the one hand, you don't want to poll
    /// in a tight loop, since that leads to excessive CPU usage. On the other hand, you don't
    /// want to sleep forever waiting for an event, since it may block other tasks running in the
    /// main event loop thread. As a rule of thumb, waiting up to 10-100 milliseconds for an event
    /// works fine.
    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), anyhow::Error>;

    /// # Get progress information
    ///
    /// If your plugin reads from a source that has a well-defined end (like a file),
    /// you can use this method to report progress information.
    ///
    /// It consists of a percentage (0.0-100.0) and an optional description containing more
    /// details about the progress (e.g. bytes read/bytes total).
    fn get_progress(&mut self) -> ProgressInfo {
        ProgressInfo {
            value: 0.0,
            detail: None,
        }
    }

    /// # A helper for generating plugin events
    ///
    /// If your plugin defines a PLUGIN_ID and a source name, the only allowed events are
    /// of type [`PluginEvent`] and effectively the only customizable field is the event data
    /// (which is a generic byte buffer).
    ///
    /// This method makes it easy to generate such events: just pass it the event data and get
    /// the complete event, with all the metadata set to reasonable defaults.
    fn plugin_event(data: &[u8]) -> Event<PluginEvent> {
        let event = PluginEvent {
            plugin_id: Some(Self::Plugin::PLUGIN_ID),
            event_data: Some(data),
        };

        let metadata = EventMetadata::default();

        Event {
            metadata,
            params: event,
        }
    }
}
