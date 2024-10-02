use crate::{
    Api, CaptureNotStarted, CaptureStarted, CapturingTestDriver, ScapStatus, SinspMetric,
    TestDriver,
};
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

pub struct SinspEvent;

pub struct SinspPlugin;

impl Debug for SinspPlugin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SinspPlugin")
    }
}

pub struct SinspTestDriver<S>(PhantomData<S>);

impl<S> Debug for SinspTestDriver<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SinspTestDriver")
    }
}

impl TestDriver for SinspTestDriver<CaptureNotStarted> {
    type Capturing = SinspTestDriver<CaptureStarted>;
    type Plugin = SinspPlugin;

    fn new() -> anyhow::Result<Self> {
        Ok(Self(PhantomData))
    }

    fn register_plugin(&mut self, _api: &Api, _config: &CStr) -> anyhow::Result<Self::Plugin> {
        anyhow::bail!("not implemented")
    }

    unsafe fn register_plugin_raw(
        &mut self,
        _api: *const Api,
        _config: &CStr,
    ) -> anyhow::Result<Self::Plugin> {
        anyhow::bail!("not implemented")
    }

    fn add_filterchecks(&mut self, _plugin: &Self::Plugin, _source: &CStr) -> anyhow::Result<()> {
        anyhow::bail!("not implemented")
    }

    fn start_capture(self, _name: &CStr, _config: &CStr) -> anyhow::Result<Self::Capturing> {
        anyhow::bail!("not implemented")
    }
}

impl CapturingTestDriver for SinspTestDriver<CaptureStarted> {
    type NonCapturing = SinspTestDriver<CaptureNotStarted>;
    type Event = SinspEvent;

    fn next_event(&mut self) -> Result<Self::Event, ScapStatus> {
        Err(ScapStatus::NotSupported)
    }

    fn event_field_as_string(
        &mut self,
        _field_name: &CStr,
        _event: &Self::Event,
    ) -> anyhow::Result<Option<String>> {
        anyhow::bail!("not implemented")
    }

    fn get_metrics(&mut self) -> anyhow::Result<Vec<SinspMetric>> {
        anyhow::bail!("not implemented")
    }
}

pub type Driver = SinspTestDriver<CaptureNotStarted>;
