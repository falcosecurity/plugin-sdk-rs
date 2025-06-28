use falco_plugin::anyhow::Error;
use falco_plugin::base::{Metric, MetricLabel, MetricType, MetricValue, Plugin};
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::source::{
    EventBatch, EventInput, PluginEvent, SourcePlugin, SourcePluginInstance,
};
use falco_plugin::strings::CStringWriter;
use falco_plugin::tables::export;
use falco_plugin::tables::import;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::io::Write;

type RemainingEntryTable = export::Table<u64, RemainingCounter>;

#[derive(export::Entry)]
struct RemainingCounter {
    remaining: export::Public<u64>,
}

struct DummyPlugin {
    num_batches: usize,
    batch_count: MetricLabel,
    remaining_table: Box<RemainingEntryTable>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;

        let remaining_table = input.add_table(RemainingEntryTable::new(c"remaining")?)?;

        Ok(Self {
            num_batches: 0,
            batch_count: MetricLabel::new(c"next_batch_call_count", MetricType::Monotonic),
            remaining_table,
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

impl ParsePlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];

    fn parse_event(&mut self, event: &EventInput, _parse_input: &ParseInput) -> anyhow::Result<()> {
        let event_num = event.event_number() as u64;
        let event = event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let first_char = &payload[0..1];
        let first_char = std::str::from_utf8(first_char)?;
        let remaining: u64 = first_char.parse()?;

        // using our table directly, bypassing the table api
        let mut entry = self.remaining_table.create_entry()?;
        *entry.remaining = remaining;
        self.remaining_table.insert(&event_num, entry);

        Ok(())
    }
}

struct DummyExtractPlugin {
    remaining_table: import::Table<u64>,
    remaining_field: import::Field<u64>,
}

impl Plugin for DummyExtractPlugin {
    const NAME: &'static CStr = c"dummy_extract";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;
        let remaining_table: import::Table<u64> = input.get_table(c"remaining")?;
        let remaining_field = remaining_table.get_field(input, c"remaining")?;

        Ok(Self {
            remaining_table,
            remaining_field,
        })
    }
}

impl DummyExtractPlugin {
    fn extract_remaining(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let remaining = entry.read_field(req.table_reader, &self.remaining_field)?;

        Ok(remaining)
    }
}

impl ExtractPlugin for DummyExtractPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("dummy_extract.remaining", &Self::extract_remaining)];
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);
static_plugin!(DUMMY_EXTRACT_API = DummyExtractPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{
        init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, ScapStatus, TestDriver,
    };

    fn test_dummy_next<D: TestDriver>() {
        let (mut driver, _plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"").unwrap();
        let extract_plugin = driver
            .register_plugin(&super::DUMMY_EXTRACT_API, c"")
            .unwrap();
        driver.add_filterchecks(&extract_plugin, c"dummy").unwrap();

        let mut driver = driver
            .start_capture(super::DummyPlugin::NAME, c"", PlatformData::Disabled)
            .unwrap();

        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.remaining", &event)
                .unwrap()
                .unwrap(),
            "3"
        );
        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.remaining", &event)
                .unwrap()
                .unwrap(),
            "2"
        );
        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.remaining", &event)
                .unwrap()
                .unwrap(),
            "1"
        );
        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.remaining", &event)
                .unwrap()
                .unwrap(),
            "0"
        );

        let event = driver.next_event();
        assert!(matches!(event, Err(ScapStatus::Eof)))
    }

    instantiate_tests!(test_dummy_next);
}
