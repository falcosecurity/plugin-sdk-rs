use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::tables::import;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin};
use std::ffi::CStr;

struct ExtractRemainingFromTableRuntime {
    remaining_table: import::Table<u64>,
    remaining_field: import::Field<u64>,
}

impl Plugin for ExtractRemainingFromTableRuntime {
    const NAME: &'static CStr = c"extract_remaining_from_table_runtime";
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

impl ExtractRemainingFromTableRuntime {
    fn extract_remaining(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let remaining = entry.read_field(req.table_reader, &self.remaining_field)?;

        Ok(remaining)
    }
}

impl ExtractPlugin for ExtractRemainingFromTableRuntime {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("countdown.remaining", &Self::extract_remaining)];
}

static_plugin!(EXTRACT_REMAINING_FROM_TABLE_RUNTIME_API = ExtractRemainingFromTableRuntime);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::plugin_collection::parse::remaining_into_table_direct::PARSE_REMAINING_INTO_TABLE_DIRECT_PLUGIN_API;
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
            .register_plugin(&PARSE_REMAINING_INTO_TABLE_DIRECT_PLUGIN_API, c"")
            .unwrap();
        let extract_plugin = driver
            .register_plugin(&super::EXTRACT_REMAINING_FROM_TABLE_RUNTIME_API, c"")
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
