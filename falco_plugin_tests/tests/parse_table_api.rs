use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
use falco_plugin::strings::WriteIntoCString;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin};
use falco_plugin_tests::plugin_collection::tables::remaining_import_extra_fields::accessors::*;
use falco_plugin_tests::plugin_collection::tables::remaining_import_extra_fields::RemainingCounterImportTableWithExtraFields;
use std::ffi::{CStr, CString};
use std::io::Write;

struct ParseExtraFields {
    remaining_table: RemainingCounterImportTableWithExtraFields,
}

impl Plugin for ParseExtraFields {
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

impl ParsePlugin for ParseExtraFields {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];

    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()> {
        let event_num = event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(&parse_input.reader, &event_num)?;
        let remaining = entry.get_remaining(&parse_input.reader)?;

        let is_even = remaining.is_multiple_of(2).into();
        let mut string_rep = CString::default();
        string_rep.write_into(|w| write!(w, "{remaining} events remaining"))?;

        entry.set_is_even(&parse_input.writer, &is_even)?;
        entry.set_as_string(&parse_input.writer, string_rep.as_c_str())?;

        Ok(())
    }
}

struct ExtractExtraFields {
    // reusing the table definition with the #[custom] annotations
    // technically causes the fields to be added again, but we get
    // the existing instances in that case
    remaining_table: RemainingCounterImportTableWithExtraFields,
}

impl Plugin for ExtractExtraFields {
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

impl ExtractExtraFields {
    fn extract_is_even(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let is_even = entry.get_is_even(req.table_reader)?;

        Ok(is_even.into())
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

impl ExtractPlugin for ExtractExtraFields {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy_extract.is_even", &Self::extract_is_even),
        field("dummy_extract.as_string", &Self::extract_string_rep),
    ];
}

static_plugin!(PARSE_EXTRA_FIELDS_API = ParseExtraFields);
static_plugin!(EXTRACT_EXTRA_FIELDS_API = ExtractExtraFields);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::plugin_collection::extract::remaining_from_table::EXTRACT_REMAINING_FROM_TABLE_API;
    use falco_plugin_tests::plugin_collection::parse::remaining_into_table_api::PARSE_INTO_TABLE_API_API;
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
            .register_plugin(&PARSE_INTO_TABLE_API_API, c"")
            .unwrap();
        let extract_remaining_plugin = driver
            .register_plugin(&EXTRACT_REMAINING_FROM_TABLE_API, c"")
            .unwrap();
        let extract_plugin = driver
            .register_plugin(&super::EXTRACT_EXTRA_FIELDS_API, c"")
            .unwrap();
        driver
            .register_plugin(&super::PARSE_EXTRA_FIELDS_API, c"")
            .unwrap();
        driver
            .add_filterchecks(&extract_remaining_plugin, c"countdown")
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
                .event_field_as_string(c"countdown.remaining", &event)
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
