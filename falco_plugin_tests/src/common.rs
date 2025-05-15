use anyhow::Context;
use cxx::{type_id, ExternType};
use std::ffi::CStr;
use std::fmt::Debug;

pub use falco_plugin_runner::ScapStatus;

pub struct CaptureNotStarted;

pub struct CaptureStarted;

#[repr(transparent)]
pub struct Api(pub falco_plugin::api::plugin_api);

unsafe impl ExternType for Api {
    type Id = type_id!("falco_plugin_api");
    type Kind = cxx::kind::Opaque;
}

pub struct SinspMetric {
    pub name: String,
    pub value: u64, // TODO: this is... taking shortcuts
}

pub trait TestDriver: Debug + Sized {
    type Capturing: CapturingTestDriver<NonCapturing = Self>;
    type Plugin: Debug;

    fn new() -> anyhow::Result<Self>;

    fn register_plugin(
        &mut self,
        api: &'static falco_plugin::api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<Self::Plugin>;

    /// # Safety
    /// `api` must be a valid pointer (or null, to be caught by the framework)
    unsafe fn register_plugin_raw(
        &mut self,
        api: *const falco_plugin::api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<Self::Plugin>;

    fn add_filterchecks(&mut self, plugin: &Self::Plugin, source: &CStr) -> anyhow::Result<()>;

    fn start_capture(self, name: &CStr, config: &CStr) -> anyhow::Result<Self::Capturing>;
}

pub trait SavefileTestDriver: TestDriver {
    fn load_capture_file(self, path: &CStr) -> anyhow::Result<Self::Capturing>;
}

pub trait CapturingTestDriver {
    type NonCapturing: TestDriver<Capturing = Self>;
    type Event;

    fn next_event(&mut self) -> Result<Self::Event, ScapStatus>;

    fn event_field_as_string(
        &mut self,
        field_name: &CStr,
        event: &Self::Event,
    ) -> anyhow::Result<Option<String>>;

    fn event_field_is_none(&mut self, field_name: &CStr, event: &Self::Event) -> bool;

    fn get_metrics(&mut self) -> anyhow::Result<Vec<SinspMetric>>;

    fn next_event_as_str(&mut self) -> anyhow::Result<Option<String>> {
        let event = match self.next_event() {
            Ok(event) => event,
            Err(e) => return Err(anyhow::anyhow!("{:?}", e)).context(e),
        };
        self.event_field_as_string(c"evt.plugininfo", &event)
    }
}
