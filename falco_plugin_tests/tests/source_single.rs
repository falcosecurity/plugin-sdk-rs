use falco_plugin::anyhow::Error;
use falco_plugin::base::{Metric, MetricLabel, MetricType, MetricValue, Plugin};
use falco_plugin::source::{
    EventBatch, EventInput, PluginEvent, SourcePlugin, SourcePluginInstance,
};
use falco_plugin::strings::CStringWriter;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::io::Write;

struct CountdownPlugin(usize);

impl Plugin for CountdownPlugin {
    const NAME: &'static CStr = c"countdown";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self(0))
    }

    fn get_metrics(&mut self) -> impl IntoIterator<Item = Metric> {
        [Metric::new(
            MetricLabel::new(c"next_batch_call_count", MetricType::Monotonic),
            MetricValue::U64(self.0 as u64),
        )]
    }
}

struct CountdownPluginInstance(usize);

impl SourcePluginInstance for CountdownPluginInstance {
    type Plugin = CountdownPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        plugin.0 += 1;
        if self.0 > 0 {
            self.0 -= 1;
            let event = format!("{} events remaining", self.0);
            let event = Self::plugin_event(event.as_bytes());
            batch.add(event)?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("all events produced").context(FailureReason::Eof))
        }
    }
}

impl SourcePlugin for CountdownPlugin {
    type Instance = CountdownPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"countdown";
    const PLUGIN_ID: u32 = 1111;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(CountdownPluginInstance(3))
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

static_plugin!(COUNTDOWN_PLUGIN_API = CountdownPlugin);

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

        assert_eq!(m.name, "countdown.next_batch_call_count");
        assert_eq!(m.value, n as u64);

        assert!(metrics.next().is_none());
    }

    fn test_dummy_next<D: TestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(&super::COUNTDOWN_PLUGIN_API, c"").unwrap();
        let mut driver = driver
            .start_capture(super::CountdownPlugin::NAME, c"", PlatformData::Disabled)
            .unwrap();

        assert_eq!(
            driver.next_event_as_str().unwrap().unwrap(),
            "2 events remaining"
        );
        check_metrics(&mut driver, 1);

        assert_eq!(
            driver.next_event_as_str().unwrap().unwrap(),
            "1 events remaining"
        );
        check_metrics(&mut driver, 2);

        assert_eq!(
            driver.next_event_as_str().unwrap().unwrap(),
            "0 events remaining"
        );
        check_metrics(&mut driver, 3);

        let event = driver.next_event();
        check_metrics(&mut driver, 4);
        assert!(matches!(event, Err(ScapStatus::Eof)))
    }

    instantiate_tests!(test_dummy_next);
}
