use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::source::EventInput;
use falco_plugin::tables::export;
use falco_plugin::tables::import;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin};
use std::ffi::CStr;
use std::sync::Arc;

type RemainingEntryTable = export::Table<u64, RemainingCounter>;

#[derive(export::Entry)]
struct RemainingCounter {
    remaining: export::Public<u64>,
}

struct ParseTestPlugin {
    remaining_table: Box<RemainingEntryTable>,
}

impl Plugin for ParseTestPlugin {
    const NAME: &'static CStr = c"test_parse";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;

        let remaining_table = input.add_table(RemainingEntryTable::new(c"remaining")?)?;

        Ok(Self { remaining_table })
    }
}

impl ParsePlugin for ParseTestPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];

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

type RemainingCounterImportTable = import::Table<u64, RemainingCounterImport>;
type RemainingCounterImport = import::Entry<Arc<RemainingCounterImportMetadata>>;

#[derive(import::TableMetadata)]
#[entry_type(RemainingCounterImport)]
struct RemainingCounterImportMetadata {
    remaining: import::Field<u64, RemainingCounterImport>,
}

struct DummyExtractPlugin {
    remaining_table: RemainingCounterImportTable,
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
    fn extract_remaining(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let remaining = entry.get_remaining(req.table_reader)?;

        Ok(remaining)
    }
}

impl ExtractPlugin for DummyExtractPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("countdown.remaining", &Self::extract_remaining)];
}

static_plugin!(PARSE_PLUGIN_API = ParseTestPlugin);
static_plugin!(DUMMY_EXTRACT_API = DummyExtractPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::plugin_collection::source::countdown::{
        CountdownPlugin, COUNTDOWN_PLUGIN_API,
    };
    use falco_plugin_tests::{
        init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, ScapStatus, TestDriver,
    };

    fn test_dummy_next<D: TestDriver>() {
        let (mut driver, _plugin) = init_plugin::<D>(
            &COUNTDOWN_PLUGIN_API,
            cr#"{"remaining": 4, "batch_size": 4}"#,
        )
        .unwrap();
        let _ = driver.register_plugin(&super::PARSE_PLUGIN_API, c"");
        let extract_plugin = driver
            .register_plugin(&super::DUMMY_EXTRACT_API, c"")
            .unwrap();
        driver
            .add_filterchecks(&extract_plugin, c"countdown")
            .unwrap();
        let mut driver = driver
            .start_capture(CountdownPlugin::NAME, c"", PlatformData::Disabled)
            .unwrap();

        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"countdown.remaining", &event)
                .unwrap()
                .unwrap(),
            "3"
        );
        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"countdown.remaining", &event)
                .unwrap()
                .unwrap(),
            "2"
        );
        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"countdown.remaining", &event)
                .unwrap()
                .unwrap(),
            "1"
        );
        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"countdown.remaining", &event)
                .unwrap()
                .unwrap(),
            "0"
        );

        let event = driver.next_event();
        assert!(matches!(event, Err(ScapStatus::Eof)))
    }

    instantiate_tests!(test_dummy_next);
}
