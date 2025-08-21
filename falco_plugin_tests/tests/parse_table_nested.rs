use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin};
use falco_plugin_tests::plugin_collection::tables::remaining_import_extra_fields::accessors::*;
use falco_plugin_tests::plugin_collection::tables::remaining_import_extra_fields::nested_accessors::*;
use falco_plugin_tests::plugin_collection::tables::remaining_import_extra_fields::RemainingCounterImportTableWithExtraFields;
use std::ffi::CStr;

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
}

impl ExtractPlugin for DummyExtractPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("dummy_extract.is_final", &Self::extract_is_final)];
}

static_plugin!(DUMMY_EXTRACT_API = DummyExtractPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::plugin_collection::extract::extra_fields::EXTRACT_EXTRA_FIELDS_API;
    use falco_plugin_tests::plugin_collection::extract::remaining_from_table::EXTRACT_REMAINING_FROM_TABLE_API;
    use falco_plugin_tests::plugin_collection::parse::nested_table_extra_fields::PARSE_NESTED_TABLE_EXTRA_FIELDS_API;
    use falco_plugin_tests::plugin_collection::parse::remaining_into_nested_table::PARSE_INTO_NESTED_TABLE_API;
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
            .register_plugin(&PARSE_INTO_NESTED_TABLE_API, c"")
            .unwrap();
        let extract_remaining_plugin = driver
            .register_plugin(&EXTRACT_REMAINING_FROM_TABLE_API, c"")
            .unwrap();
        let extract_extra_fields_plugin = driver
            .register_plugin(&EXTRACT_EXTRA_FIELDS_API, c"")
            .unwrap();
        let extract_plugin = driver
            .register_plugin(&super::DUMMY_EXTRACT_API, c"")
            .unwrap();
        driver
            .register_plugin(&PARSE_NESTED_TABLE_EXTRA_FIELDS_API, c"")
            .unwrap();
        driver
            .add_filterchecks(&extract_remaining_plugin, c"countdown")
            .unwrap();
        driver
            .add_filterchecks(&extract_extra_fields_plugin, c"countdown")
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
                .event_field_as_string(c"countdown.is_even", &event)
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
                .event_field_as_string(c"countdown.as_string", &event)
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
                .event_field_as_string(c"countdown.is_even", &event)
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
                .event_field_as_string(c"countdown.as_string", &event)
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
