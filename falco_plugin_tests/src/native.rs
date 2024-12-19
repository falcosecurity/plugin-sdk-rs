use crate::{CapturingTestDriver, ScapStatus, SinspMetric, TestDriver};
use falco_plugin_runner::{CapturingPluginRunner, MetricValue, PluginRunner};
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};

pub struct NativePlugin;

impl Debug for NativePlugin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativePlugin")
    }
}

pub struct NativeTestDriver(PluginRunner);

pub struct NativeCapturingTestDriver(CapturingPluginRunner);

impl Debug for NativeTestDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeTestDriver")
    }
}

impl Debug for NativeCapturingTestDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeCapturingTestDriver")
    }
}

impl TestDriver for NativeTestDriver {
    type Capturing = NativeCapturingTestDriver;
    type Plugin = NativePlugin;

    fn new() -> anyhow::Result<Self> {
        Ok(Self(PluginRunner::new()))
    }

    fn register_plugin(
        &mut self,
        api: &'static falco_plugin::api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<Self::Plugin> {
        self.0.register_plugin(api, config)?;
        Ok(NativePlugin)
    }

    unsafe fn register_plugin_raw(
        &mut self,
        api: *const falco_plugin::api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<Self::Plugin> {
        // no point in making the PluginRunner support raw pointers, just handle it here
        anyhow::ensure!(!api.is_null(), "null pointer in register_plugin");
        let api: &'static falco_plugin::api::plugin_api = &*api;
        self.0.register_plugin(api, config)?;
        Ok(NativePlugin)
    }

    fn add_filterchecks(&mut self, _plugin: &Self::Plugin, _source: &CStr) -> anyhow::Result<()> {
        // filterchecks are automatically registered with the native runner
        Ok(())
    }

    fn start_capture(self, _name: &CStr, _config: &CStr) -> anyhow::Result<Self::Capturing> {
        let capturing = self.0.start_capture()?;
        Ok(NativeCapturingTestDriver(capturing))
    }
}

impl CapturingTestDriver for NativeCapturingTestDriver {
    type NonCapturing = NativeTestDriver;
    type Event = falco_plugin_runner::Event;

    fn next_event(&mut self) -> Result<Self::Event, ScapStatus> {
        match self.0.next_event() {
            Ok(evt) => Ok(evt),
            Err(e) => match e.downcast_ref::<ScapStatus>() {
                Some(ss) => Err(*ss),
                None => Err(ScapStatus::Failure),
            },
        }
    }

    fn event_field_as_string(
        &mut self,
        field_name: &CStr,
        event: &Self::Event,
    ) -> anyhow::Result<Option<String>> {
        let s = std::str::from_utf8(field_name.to_bytes())?;
        match self.0.extract_field(event, s) {
            None => Ok(None),
            Some(Err(e)) => Err(anyhow::anyhow!("failed to extract field: {}", e)),
            Some(Ok(s)) => Ok(Some(s.to_string())),
        }
    }

    fn get_metrics(&mut self) -> anyhow::Result<Vec<SinspMetric>> {
        let metrics = self.0.get_metrics();
        Ok(metrics
            .into_iter()
            .flat_map(|m| {
                let value = match m.value {
                    MetricValue::S32(v) => v as u64,
                    MetricValue::U32(v) => v as u64,
                    MetricValue::U64(v) => v,
                    MetricValue::I64(v) => v as u64,
                    MetricValue::Double(v) => v as u64,
                    MetricValue::Float(v) => v as u64,
                    MetricValue::Int(v) => v as u64,
                };

                Some(SinspMetric {
                    name: m.name,
                    value,
                })
            })
            .collect())
    }
}

pub type Driver = NativeTestDriver;
