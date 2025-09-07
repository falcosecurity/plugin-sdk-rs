use anyhow::Context;
use falco_event::events::RawEvent;
use falco_plugin_api::ss_plugin_event_input;
use std::ffi::CStr;
use std::marker::PhantomData;

/// # An event from which additional data may be extracted
#[derive(Debug)]
pub struct EventInput<'a, T>(
    pub(crate) ss_plugin_event_input,
    pub(crate) PhantomData<fn(&'a T)>,
);

impl<'a, T> EventInput<'a, T>
where
    for<'b> T: TryFrom<&'b RawEvent<'a>>,
    for<'b> <T as TryFrom<&'b RawEvent<'a>>>::Error: std::error::Error + Send + Sync + 'static,
{
    /// # Get the event
    ///
    /// This method parses the raw event data into another type, e.g. a [`RawEvent`] instance,
    /// or a specific event type.
    pub fn event(&self) -> anyhow::Result<T> {
        let raw = unsafe { RawEvent::from_ptr(self.0.evt as *const _) }?;
        let event = Ok(<&RawEvent<'_> as TryInto<T>>::try_into(&raw)
            .with_context(|| format!("parsing event {raw:?}"))?);
        #[allow(clippy::let_and_return)]
        event
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
