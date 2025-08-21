use crate::plugin_collection::tables::remaining_export::RemainingEntryTable;
use crate::plugin_collection::tables::remaining_import::accessors::*;
use crate::plugin_collection::tables::remaining_import::RemainingCounterImportTable;
use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::EventInput;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;

struct ParseIntoTableApiPlugin {
    #[allow(unused)]
    remaining_table: Box<RemainingEntryTable>,
    remaining_table_import: RemainingCounterImportTable,
}

impl Plugin for ParseIntoTableApiPlugin {
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
            remaining_table,
            remaining_table_import,
        })
    }
}

impl ParsePlugin for ParseIntoTableApiPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];

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
        anyhow::ensure!(
            entry.set_readonly(w, &1).is_err(),
            "setting a read-only field succeeded"
        );
        let _ = self
            .remaining_table_import
            .insert(r, w, &event_num, entry)?;

        Ok(())
    }
}

static_plugin!(pub PARSE_INTO_TABLE_API_API = ParseIntoTableApiPlugin);
