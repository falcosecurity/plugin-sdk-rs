use falco_plugin::anyhow::Error;
use falco_plugin::base::{Metric, MetricLabel, MetricType, MetricValue, Plugin};
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::{
    field, ExtractFieldInfo, ExtractFieldRequestArg, ExtractPlugin, ExtractRequest,
};
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::source::{
    EventBatch, EventInput, PluginEvent, SourcePlugin, SourcePluginInstance,
};
use falco_plugin::strings::{CStringWriter, WriteIntoCString};
use falco_plugin::tables::export;
use falco_plugin::tables::import;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::sync::Arc;

// exporting a table
type RemainingEntryTable = export::Table<u64, RemainingCounter>;

// TODO Entry vs TableMetadata is an ugly asymmetry
#[derive(export::Entry)]
struct RemainingCounter {
    remaining: export::Public<u64>,
}

// same table, but imported
type RemainingCounterImportTable = import::Table<u64, RemainingCounterImport>;
type RemainingCounterImport = import::Entry<Arc<RemainingCounterImportMetadata>>;

#[derive(import::TableMetadata)]
#[entry_type(RemainingCounterImport)]
struct RemainingCounterImportMetadata {
    remaining: import::Field<u64, RemainingCounterImport>,
}

struct DummyPlugin {
    num_batches: usize,
    batch_count: MetricLabel,
    #[allow(unused)]
    remaining_table: Box<RemainingEntryTable>,
    remaining_table_import: RemainingCounterImportTable,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;

        // add the table (must hold the resulting Box to keep the table alive)
        let remaining_table = input.add_table(RemainingEntryTable::new(c"remaining")?)?;
        let remaining_table_import = input.get_table(c"remaining")?;

        Ok(Self {
            num_batches: 0,
            batch_count: MetricLabel::new(c"next_batch_call_count", MetricType::Monotonic),
            remaining_table,
            remaining_table_import,
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
                let event = format!("{} events remaining", num_events);
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

    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()> {
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

        // use table API
        let r = &parse_input.reader;
        let w = &parse_input.writer;
        let entry = self.remaining_table_import.create_entry(w)?;
        entry.set_remaining(w, &remaining)?;
        let _ = self
            .remaining_table_import
            .insert(r, w, &event_num, entry)?;

        Ok(())
    }
}

// now, redefine the table but add some extra fields
type RemainingCounterImportTableWithExtraFields =
    import::Table<u64, RemainingCounterImportWithExtraFields>;
type RemainingCounterImportWithExtraFields =
    import::Entry<Arc<RemainingCounterImportMetadataWithExtraFields>>;

#[derive(import::TableMetadata)]
#[entry_type(RemainingCounterImportWithExtraFields)]
struct RemainingCounterImportMetadataWithExtraFields {
    remaining: import::Field<u64, RemainingCounterImportWithExtraFields>,

    #[custom]
    is_even: import::Field<import::Bool, RemainingCounterImportWithExtraFields>,
    #[custom]
    as_string: import::Field<CStr, RemainingCounterImportWithExtraFields>,
}

struct DummyParsePlugin {
    remaining_table: RemainingCounterImportTableWithExtraFields,
}

impl Plugin for DummyParsePlugin {
    const NAME: &'static CStr = c"dummy_parse";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;
        let remaining_table = input.get_table(c"remaining")?;

        Ok(Self { remaining_table })
    }
}

impl ParsePlugin for DummyParsePlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];

    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()> {
        let event_num = event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(&parse_input.reader, &event_num)?;
        let remaining = entry.get_remaining(&parse_input.reader)?;

        let is_even = (remaining % 2 == 0).into();
        let mut string_rep = CString::default();
        string_rep.write_into(|w| write!(w, "{} events remaining", remaining))?;

        entry.set_is_even(&parse_input.writer, &is_even)?;
        entry.set_as_string(&parse_input.writer, string_rep.as_c_str())?;

        Ok(())
    }
}

struct DummyExtractPlugin {
    // reusing the table definition with the #[custom] annotations
    // technically causes the fields to be added again, but we get
    // the existing instances in that case
    remaining_table: RemainingCounterImportTableWithExtraFields,
}

impl Plugin for DummyExtractPlugin {
    const NAME: &'static CStr = c"dummy_extract";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;
        let remaining_table = input.get_table(c"remaining")?;

        Ok(Self { remaining_table })
    }
}

impl DummyExtractPlugin {
    fn extract_remaining(
        &mut self,
        req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let remaining = entry.get_remaining(req.table_reader)?;

        Ok(remaining)
    }

    fn extract_is_even(
        &mut self,
        req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let is_even = entry.get_is_even(req.table_reader)?;

        Ok(is_even.into())
    }

    fn extract_string_rep(
        &mut self,
        req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<CString, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let string_rep = entry.get_as_string(req.table_reader)?;

        Ok(CString::from(string_rep))
    }
}

impl ExtractPlugin for DummyExtractPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy_extract.remaining", &Self::extract_remaining),
        field("dummy_extract.is_even", &Self::extract_is_even),
        field("dummy_extract.as_string", &Self::extract_string_rep),
    ];
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);
static_plugin!(DUMMY_PARSE_API = DummyParsePlugin);
static_plugin!(DUMMY_EXTRACT_API = DummyExtractPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{init_plugin, Api, ScapStatus};

    #[test]
    fn test_dummy_next() {
        let (mut driver, _plugin) = init_plugin(super::DUMMY_PLUGIN_API, c"").unwrap();
        let extract_plugin = driver
            .register_plugin(&Api(super::DUMMY_EXTRACT_API), c"")
            .unwrap();
        driver
            .register_plugin(&Api(super::DUMMY_PARSE_API), c"")
            .unwrap();
        driver.add_filterchecks(&extract_plugin, c"dummy").unwrap();

        let mut driver = driver.start_capture(super::DummyPlugin::NAME, c"").unwrap();

        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.remaining", &event)
                .unwrap()
                .unwrap(),
            "3"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.is_even", &event)
                .unwrap()
                .unwrap(),
            "0"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.as_string", &event)
                .unwrap()
                .unwrap(),
            "3 events remaining"
        );

        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.remaining", &event)
                .unwrap()
                .unwrap(),
            "2"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.is_even", &event)
                .unwrap()
                .unwrap(),
            "1"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.as_string", &event)
                .unwrap()
                .unwrap(),
            "2 events remaining"
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
}
