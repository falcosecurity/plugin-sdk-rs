use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
use falco_plugin::strings::WriteIntoCString;
use falco_plugin::tables::import;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin};
use falco_plugin_tests::plugin_collection::tables::remaining_export::RemainingEntryTable;
use std::ffi::{CStr, CString};
use std::io::Write;
use std::ops::ControlFlow;
use std::sync::Arc;

struct DummyPlugin {
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

        // add the table
        let remaining_table = input.add_table(RemainingEntryTable::new(c"remaining")?)?;

        Ok(Self { remaining_table })
    }
}

impl ParsePlugin for DummyPlugin {
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

        let mut entry = self.remaining_table.create_entry()?;
        *entry.remaining = remaining;

        {
            let countdown_table = &mut entry.countdown;
            for i in 0..=remaining {
                let mut countdown_entry = countdown_table.create_entry()?;
                *countdown_entry.count = remaining - i;

                let _ = countdown_table
                    .insert(&i, countdown_entry)
                    .ok_or_else(|| anyhow::anyhow!("boo"))?;
            }
        }

        let _ = self
            .remaining_table
            .insert(&event_num, entry)
            .ok_or_else(|| anyhow::anyhow!("boo"))?;
        Ok(())
    }
}

// now, redefine the tables but add some extra fields
type RemainingCounterImportTableWithExtraFields =
    import::Table<u64, RemainingCounterImportWithExtraFields>;
type RemainingCounterImportWithExtraFields =
    import::Entry<Arc<RemainingCounterImportMetadataWithExtraFields>>;

#[derive(import::TableMetadata)]
#[entry_type(RemainingCounterImportWithExtraFields)]
struct RemainingCounterImportMetadataWithExtraFields {
    remaining: import::Field<u64, RemainingCounterImportWithExtraFields>,
    countdown:
        import::Field<CountdownImportTableWithExtraFields, RemainingCounterImportWithExtraFields>,

    #[custom]
    is_even: import::Field<import::Bool, RemainingCounterImportWithExtraFields>,
    #[custom]
    as_string: import::Field<CStr, RemainingCounterImportWithExtraFields>,
}

type CountdownImportTableWithExtraFields = import::Table<u64, CountdownImportWithExtraFields>;
type CountdownImportWithExtraFields = import::Entry<Arc<CountdownImportMetadataWithExtraFields>>;

#[derive(import::TableMetadata)]
#[entry_type(CountdownImportWithExtraFields)]
struct CountdownImportMetadataWithExtraFields {
    count: import::Field<u64, CountdownImportWithExtraFields>,

    #[custom]
    // Europe intensifies
    is_final: import::Field<import::Bool, CountdownImportWithExtraFields>,
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
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];

    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()> {
        let reader = &parse_input.reader;
        let writer = &parse_input.writer;
        let event_num = event.event_number() as u64;

        let entry = self.remaining_table.get_entry(reader, &event_num)?;
        let remaining = entry.get_remaining(reader)?;

        let is_even = remaining.is_multiple_of(2).into();
        let mut string_rep = CString::default();
        string_rep.write_into(|w| write!(w, "{remaining} events remaining"))?;

        entry.set_is_even(writer, &is_even)?;
        entry.set_as_string(writer, string_rep.as_c_str())?;

        entry.get_countdown(reader)?.iter_entries_mut(reader, |c| {
            // TODO: some error handling support would be nice
            let Ok(count) = c.get_count(reader) else {
                return ControlFlow::Continue(());
            };

            let is_final = (count == 0).into();
            // TODO again, error handling
            c.set_is_final(writer, &is_final).ok();

            ControlFlow::Continue(())
        })?;

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
    fn extract_remaining(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let remaining = entry.get_remaining(req.table_reader)?;

        Ok(remaining)
    }

    fn extract_is_even(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let is_even = entry.get_is_even(req.table_reader)?;

        Ok(is_even.into())
    }

    fn extract_is_final(&mut self, req: ExtractRequest<Self>, arg: u64) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;

        let is_final = entry
            .get_countdown_by_key(req.table_reader, &arg)?
            .get_is_final(req.table_reader)?;

        Ok(is_final.into())
    }

    fn extract_string_rep(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
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
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy_extract.remaining", &Self::extract_remaining),
        field("dummy_extract.is_even", &Self::extract_is_even),
        field("dummy_extract.is_final", &Self::extract_is_final),
        field("dummy_extract.as_string", &Self::extract_string_rep),
    ];
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);
static_plugin!(DUMMY_PARSE_API = DummyParsePlugin);
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
        driver
            .register_plugin(&super::DUMMY_PLUGIN_API, c"")
            .unwrap();
        let extract_plugin = driver
            .register_plugin(&super::DUMMY_EXTRACT_API, c"")
            .unwrap();
        driver
            .register_plugin(&super::DUMMY_PARSE_API, c"")
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
                .event_field_as_string(c"dummy_extract.is_final[3]", &event)
                .unwrap()
                .unwrap(),
            "1"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.is_final[0]", &event)
                .unwrap()
                .unwrap(),
            "0"
        );
        assert!(driver
            .event_field_as_string(c"dummy_extract.is_final[4]", &event)
            .is_err());
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
                .event_field_as_string(c"dummy_extract.is_final[2]", &event)
                .unwrap()
                .unwrap(),
            "1"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy_extract.is_final[0]", &event)
                .unwrap()
                .unwrap(),
            "0"
        );
        assert!(driver
            .event_field_as_string(c"dummy_extract.is_final[3]", &event)
            .is_err());
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

    instantiate_tests!(test_dummy_next);
}
