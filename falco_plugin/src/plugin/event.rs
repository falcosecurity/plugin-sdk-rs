use falco_event::events::RawEvent;
use std::ffi::CStr;

pub use falco_plugin_api::ss_plugin_event_input;

/// # An event from which additional data may be extracted
#[derive(Debug)]
pub struct EventInput(pub(crate) ss_plugin_event_input);

impl EventInput {
    /// # Get the event
    ///
    /// This method parses the raw event data into a [`RawEvent`] instance,
    /// which can be later converted into a specific event type.
    pub fn event(&self) -> std::io::Result<RawEvent<'_>> {
        unsafe { RawEvent::from_ptr(self.0.evt as *const _) }
    }

    /// # Get the event source
    ///
    /// Return the event source (if any)
    pub fn source(&self) -> Option<&CStr> {
        unsafe {
            if self.0.evtsrc.is_null() {
                None
            } else {
                Some(CStr::from_ptr(self.0.evtsrc))
            }
        }
    }

    /// # Get the event number
    ///
    /// Return the event number as determined by the plugin framework
    pub fn event_number(&self) -> usize {
        self.0.evtnum as usize
    }
}
