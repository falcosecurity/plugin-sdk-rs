use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::Event;
use falco_plugin::event::{EventInput, PluginEvent};
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::{FieldTypeId, TablesInput};
use falco_plugin_tests::plugin_collection::events::countdown::Countdown;
use falco_plugin_tests::plugin_collection::parse::remaining_into_table_direct::PARSE_REMAINING_INTO_TABLE_DIRECT_PLUGIN_API;
use falco_plugin_tests::plugin_collection::source::countdown::COUNTDOWN_PLUGIN_API;
use falco_plugin_tests::plugin_collection::tables::remaining_import::RemainingCounterImportTable;
use falco_plugin_tests::{init_plugin, instantiate_tests, TestDriver};
use std::ffi::CStr;

struct ListTablesPlugin {
    #[allow(unused)]
    remaining_table_import: RemainingCounterImportTable,
}

impl Plugin for ListTablesPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;

        let tables = input.list_tables();
        let mut found_remaining = false;
        for table in tables {
            if table.name() == "remaining" {
                found_remaining = true;
                anyhow::ensure!(table.key_type() == Ok(FieldTypeId::U64));
            }
        }
        anyhow::ensure!(found_remaining);

        let remaining_table_import: RemainingCounterImportTable = input.get_table(c"remaining")?;

        Ok(Self {
            remaining_table_import,
        })
    }
}

impl ParsePlugin for ListTablesPlugin {
    type Event<'a> = Event<PluginEvent<Countdown<'a>>>;

    fn parse_event(
        &mut self,
        _event: &EventInput<Self::Event<'_>>,
        _parse_input: &ParseInput,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

static_plugin!(pub LIST_TABLES_API = ListTablesPlugin);

fn test_list_tables<D: TestDriver>() {
    let (mut driver, _plugin) = init_plugin::<D>(
        &COUNTDOWN_PLUGIN_API,
        cr#"{"remaining": 4, "batch_size": 4}"#,
    )
    .unwrap();
    driver
        .register_plugin(&PARSE_REMAINING_INTO_TABLE_DIRECT_PLUGIN_API, c"")
        .unwrap();
    driver.register_plugin(&LIST_TABLES_API, c"").unwrap();
}

instantiate_tests!(test_list_tables);
