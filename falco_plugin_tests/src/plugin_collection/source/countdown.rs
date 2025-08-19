use crate::CapturingTestDriver;
use anyhow::Error;
use falco_plugin::base::{Json, Metric, MetricLabel, MetricType, MetricValue, Plugin};
use falco_plugin::event::events::types::PPME_PLUGINEVENT_E as PluginEvent;
use falco_plugin::extract::EventInput;
use falco_plugin::source::{EventBatch, SourcePlugin, SourcePluginInstance};
use falco_plugin::strings::CStringWriter;
use falco_plugin::tables::TablesInput;
use falco_plugin::{static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::io::Write;

#[derive(Debug, serde::Deserialize, falco_plugin::schemars::JsonSchema)]
#[schemars(crate = "falco_plugin::schemars")]
pub struct CountdownConfig {
    remaining: usize,
    batch_size: usize,
}

pub struct CountdownPlugin {
    num_batches: usize,
    num_events: usize,

    remaining: usize,
    batch_size: usize,
}

impl Plugin for CountdownPlugin {
    const NAME: &'static CStr = c"countdown";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = Json<CountdownConfig>;

    fn new(_input: Option<&TablesInput>, Json(config): Self::ConfigType) -> Result<Self, Error> {
        Ok(Self {
            num_batches: 0,
            num_events: 0,

            remaining: config.remaining,
            batch_size: config.batch_size,
        })
    }

    fn get_metrics(&mut self) -> impl IntoIterator<Item = Metric> {
        [
            Metric::new(
                MetricLabel::new(c"next_batch_call_count", MetricType::Monotonic),
                MetricValue::U64(self.num_batches as u64),
            ),
            Metric::new(
                MetricLabel::new(c"events_produced", MetricType::Monotonic),
                MetricValue::U64(self.num_events as u64),
            ),
        ]
    }
}

pub struct CountdownPluginInstance {
    remaining: usize,
    batch_size: usize,
}

impl SourcePluginInstance for CountdownPluginInstance {
    type Plugin = CountdownPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        plugin.num_batches += 1;
        if self.remaining > 0 {
            let batch_size = std::cmp::min(self.remaining, self.batch_size);
            for _ in 0..batch_size {
                self.remaining -= 1;
                plugin.num_events += 1;
                let event = format!("{} events remaining", self.remaining);
                let event = Self::plugin_event(event.as_bytes());
                batch.add(event)?;
            }
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
        Ok(CountdownPluginInstance {
            remaining: self.remaining,
            batch_size: self.batch_size,
        })
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

static_plugin!(pub COUNTDOWN_PLUGIN_API = CountdownPlugin);

#[track_caller]
pub fn check_metrics<C: CapturingTestDriver>(driver: &mut C, batches: usize, events: usize) {
    let metrics = driver.get_metrics().unwrap();
    let mut metrics = metrics.iter();

    let m = metrics.next().unwrap();
    assert_eq!(m.name, "countdown.next_batch_call_count");
    assert_eq!(m.value, batches as u64);

    let m = metrics.next().unwrap();
    assert_eq!(m.name, "countdown.events_produced");
    assert_eq!(m.value, events as u64);

    assert!(metrics.next().is_none());
}
