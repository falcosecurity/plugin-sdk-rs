use falco_plugin::anyhow::Error;
use falco_plugin::base::{Metric, MetricLabel, MetricType, MetricValue, Plugin};
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::{
    field, ExtractByteRange, ExtractFieldInfo, ExtractPlugin, ExtractRequest,
};
use falco_plugin::source::{
    EventBatch, EventInput, PluginEvent, SourcePlugin, SourcePluginInstance,
};
use falco_plugin::strings::{CStringWriter, WriteIntoCString};
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::io::Write;

struct DummyPlugin {
    num_batches: usize,
    batch_count: MetricLabel,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self {
            num_batches: 0,
            batch_count: MetricLabel::new(c"next_batch_call_count", MetricType::Monotonic),
        })
    }

    fn get_metrics(&mut self) -> impl IntoIterator<Item = Metric> {
        [self
            .batch_count
            .with_value(MetricValue::U64(self.num_batches as u64))]
    }
}

struct DummyPluginInstance(Option<usize>);

impl SourcePluginInstance for DummyPluginInstance {
    type Plugin = DummyPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        plugin.num_batches += 1;
        if let Some(mut num_events) = self.0.take() {
            while num_events > 0 {
                num_events -= 1;
                let event = format!("{num_events} events remaining");
                let event = Self::plugin_event(event.as_bytes());
                batch.add(event)?;
            }
            Ok(())
        } else {
            Err(anyhow::anyhow!("all events produced").context(FailureReason::Eof))
        }
    }
}

impl SourcePlugin for DummyPlugin {
    type Instance = DummyPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"dummy";
    const PLUGIN_ID: u32 = 1111;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(DummyPluginInstance(Some(4)))
    }

    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
        let event = event.event()?;
        let plugin_event = event.load::<PluginEvent>()?;
        let mut writer = CStringWriter::default();
        write!(
            writer,
            "{}",
            plugin_event
                .params
                .event_data
                .map(|e| String::from_utf8_lossy(e))
                .unwrap_or_default()
        )?;
        Ok(writer.into_cstring())
    }
}

impl DummyPlugin {
    fn extract_payload(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let mut out = CString::default();
        out.write_into(|w| w.write_all(payload))?;

        Ok(out)
    }

    fn extract_payload_with_range(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let mut out = CString::default();
        out.write_into(|w| w.write_all(payload))?;

        if *req.offset == ExtractByteRange::Requested {
            *req.offset = ExtractByteRange::in_plugin_data(0..payload.len());
        }

        Ok(out)
    }
}

impl ExtractPlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy.payload", &Self::extract_payload),
        field(
            "dummy.payload_with_range",
            &Self::extract_payload_with_range,
        ),
    ];
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin::extract::INVALID_RANGE;
    use falco_plugin_tests::{
        init_plugin, instantiate_tests, AsPtr, CapturingTestDriver, PlatformData, TestDriver,
    };

    fn test_without_range<D: TestDriver>() {
        let (mut driver, plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"").unwrap();
        driver.add_filterchecks(&plugin, c"dummy").unwrap();
        let mut driver = driver
            .start_capture(super::DummyPlugin::NAME, c"", PlatformData::Disabled)
            .unwrap();

        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string_with_range(c"dummy.payload", &event)
                .unwrap()
                .unwrap(),
            ("3 events remaining".to_string(), INVALID_RANGE),
        );
    }

    fn test_with_range<D: TestDriver>() {
        let (mut driver, plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"").unwrap();
        driver.add_filterchecks(&plugin, c"dummy").unwrap();
        let mut driver = driver
            .start_capture(super::DummyPlugin::NAME, c"", PlatformData::Disabled)
            .unwrap();

        let event = driver.next_event().unwrap();

        let (val, range) = driver
            .event_field_as_string_with_range(c"dummy.payload_with_range", &event)
            .unwrap()
            .unwrap();

        assert_eq!(val, "3 events remaining");

        let raw = event.as_ptr();
        let raw_range =
            unsafe { std::slice::from_raw_parts(raw.add(range.start), range.end - range.start) };
        assert_eq!(raw_range, &b"3 events remaining"[..]);
    }

    instantiate_tests!(test_without_range; test_with_range);
}
