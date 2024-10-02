use anyhow::Context;
use cxx::{type_id, ExternType};
use std::ffi::CStr;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum ScapStatus {
    Ok,
    Failure,
    Timeout,
    Eof,
    NotSupported,
    Other(i32),
}

impl Display for ScapStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScapStatus::Ok => f.write_str("OK"),
            ScapStatus::Failure => f.write_str("Failure"),
            ScapStatus::Timeout => f.write_str("Timeout"),
            ScapStatus::Eof => f.write_str("Eof"),
            ScapStatus::NotSupported => f.write_str("NotSupported"),
            ScapStatus::Other(rc) => write!(f, "Other({})", rc),
        }
    }
}

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
    pub value: u64,
}

pub trait TestDriver: Debug + Sized {
    type Capturing: CapturingTestDriver<NonCapturing = Self>;
    type Plugin: Debug;

    fn new() -> anyhow::Result<Self>;

    fn register_plugin(&mut self, api: &Api, config: &CStr) -> anyhow::Result<Self::Plugin>;

    /// # Safety
    /// `api` must be a valid pointer (or null, to be caught by the framework)
    unsafe fn register_plugin_raw(
        &mut self,
        api: *const Api,
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

    fn get_metrics(&mut self) -> anyhow::Result<Vec<SinspMetric>>;

    fn next_event_as_str(&mut self) -> anyhow::Result<Option<String>> {
        let event = match self.next_event() {
            Ok(event) => event,
            Err(e) => return Err(anyhow::anyhow!("{:?}", e)).context(e),
        };
        self.event_field_as_string(c"evt.plugininfo", &event)
    }
}
