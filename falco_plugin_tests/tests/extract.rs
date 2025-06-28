use anyhow::Context;
use falco_plugin::anyhow::Error;
use falco_plugin::base::{Metric, MetricLabel, MetricType, MetricValue, Plugin};
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
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

    fn extract_payload_repeated(
        &mut self,
        req: ExtractRequest<Self>,
        reps: u64,
    ) -> Result<Vec<CString>, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let mut out = CString::default();
        out.write_into(|w| w.write_all(payload))?;
        Ok(vec![out; reps as usize])
    }

    fn extract_events_remaining(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let first_char = &payload[0..1];
        let first_char = std::str::from_utf8(first_char)?;
        let remaining = first_char.parse()?;
        Ok(remaining)
    }

    fn events_remaining_repeated(
        &mut self,
        req: ExtractRequest<Self>,
        reps: u64,
    ) -> Result<Vec<u64>, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let first_char = &payload[0..1];
        let first_char = std::str::from_utf8(first_char)?;
        let remaining: u64 = first_char.parse()?;
        Ok(vec![remaining; reps as usize])
    }

    fn extract_events_remaining_with_maybe_override(
        &mut self,
        req: ExtractRequest<Self>,
        arg: Option<&CStr>,
    ) -> Result<u64, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;

        let buf = match arg {
            Some(s) => s.to_bytes(),
            None => event
                .params
                .event_data
                .ok_or_else(|| anyhow::anyhow!("no payload in event"))?,
        };

        let first_char = &buf[0..1];
        let first_char = std::str::from_utf8(first_char).context(format!("buf={buf:?}"))?;
        let remaining = first_char.parse()?;
        Ok(remaining)
    }
}

impl ExtractPlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy.payload", &Self::extract_payload),
        field("dummy.payload_repeated", &Self::extract_payload_repeated),
        field("dummy.remaining", &Self::extract_events_remaining),
        field("dummy.remaining_repeated", &Self::events_remaining_repeated),
        field(
            "dummy.remaining_with_maybe_override",
            &Self::extract_events_remaining_with_maybe_override,
        ),
    ];
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{
        init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, ScapStatus, TestDriver,
    };

    fn check_metrics<C: CapturingTestDriver>(driver: &mut C, n: usize) {
        let metrics = driver.get_metrics().unwrap();
        let mut metrics = metrics.iter();

        let m = metrics.next().unwrap();

        assert_eq!(m.name, "dummy.next_batch_call_count");
        assert_eq!(m.value, n as u64);

        assert!(metrics.next().is_none());
    }

    fn test_dummy_next<D: TestDriver>() {
        let (mut driver, plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"").unwrap();
        driver.add_filterchecks(&plugin, c"dummy").unwrap();
        let mut driver = driver
            .start_capture(super::DummyPlugin::NAME, c"", PlatformData::Disabled)
            .unwrap();

        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"evt.plugininfo", &event)
                .unwrap()
                .unwrap(),
            "3 events remaining"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.payload", &event)
                .unwrap()
                .unwrap(),
            "3 events remaining"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.payload_repeated[2]", &event)
                .unwrap()
                .unwrap(),
            "(3 events remaining,3 events remaining)"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.remaining", &event)
                .unwrap()
                .unwrap(),
            "3"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.remaining_with_maybe_override", &event)
                .unwrap()
                .unwrap(),
            "3"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.remaining_with_maybe_override[7eleven]", &event)
                .unwrap()
                .unwrap(),
            "7"
        );
        assert!(driver
            .event_field_as_string(c"dummy.remaining_with_maybe_override[eleven]", &event)
            .is_err());
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.remaining_repeated[5]", &event)
                .unwrap()
                .unwrap(),
            "(3,3,3,3,3)"
        );
        check_metrics(&mut driver, 1);

        assert_eq!(
            driver.next_event_as_str().unwrap().unwrap(),
            "2 events remaining"
        );
        check_metrics(&mut driver, 1);

        assert_eq!(
            driver.next_event_as_str().unwrap().unwrap(),
            "1 events remaining"
        );
        check_metrics(&mut driver, 1);

        assert_eq!(
            driver.next_event_as_str().unwrap().unwrap(),
            "0 events remaining"
        );

        let event = driver.next_event();
        check_metrics(&mut driver, 2);
        assert!(matches!(event, Err(ScapStatus::Eof)))
    }

    instantiate_tests!(test_dummy_next);
}
