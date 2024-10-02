use crate::{Api, CaptureNotStarted, CaptureStarted, ScapStatus, SinspMetric};
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

impl SinspTestDriver<CaptureNotStarted> {
    pub fn register_plugin(&mut self, _api: &Api, _config: &CStr) -> anyhow::Result<SinspPlugin> {
        anyhow::bail!("not implemented")
    }

    /// # Safety
    ///
    /// `plugin` must be a pointer accepted by the sinsp API
    pub unsafe fn register_plugin_raw(
        &mut self,
        _api: *const Api,
        _config: &CStr,
    ) -> anyhow::Result<SinspPlugin> {
        anyhow::bail!("not implemented")
    }

    pub fn add_filterchecks(
        &mut self,
        _plugin: &SinspPlugin,
        _source: &CStr,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not implemented")
    }

    pub fn load_capture_file(
        self,
        _path: &CStr,
    ) -> anyhow::Result<SinspTestDriver<CaptureStarted>> {
        anyhow::bail!("not implemented")
    }

    pub fn start_capture(
        self,
        _name: &CStr,
        _config: &CStr,
    ) -> anyhow::Result<SinspTestDriver<CaptureStarted>> {
        anyhow::bail!("not implemented")
    }
}

impl SinspTestDriver<CaptureStarted> {
    pub fn next_event(&mut self) -> Result<SinspEvent, ScapStatus> {
        Err(ScapStatus::NotSupported)
    }

    pub fn event_field_as_string(
        &mut self,
        _field_name: &CStr,
        _event: &SinspEvent,
    ) -> anyhow::Result<Option<String>> {
        anyhow::bail!("not implemented")
    }

    pub fn get_metrics(&mut self) -> anyhow::Result<Vec<SinspMetric>> {
        anyhow::bail!("not implemented")
    }
}

pub fn new_test_driver() -> anyhow::Result<SinspTestDriver<CaptureNotStarted>> {
    Ok(SinspTestDriver::<CaptureNotStarted>(PhantomData))
}
