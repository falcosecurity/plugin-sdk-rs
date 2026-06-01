use crate::plugin_collection::events::countdown::Countdown;
use crate::plugin_collection::tables::remaining_export::RemainingEntryTable;
use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::Event;
use falco_plugin::extract::EventInput;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::source::PluginEvent;
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;

struct ParseIntoNestedTable {
    remaining_table: RemainingEntryTable,
}

impl Plugin for ParseIntoNestedTable {
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

impl ParsePlugin for ParseIntoNestedTable {
    type Event<'a> = Event<PluginEvent<Countdown<'a>>>;

    fn parse_event(
        &mut self,
        event: &EventInput<Self::Event<'_>>,
        _parse_input: &ParseInput,
    ) -> anyhow::Result<()> {
        let event_num = event.event_number() as u64;
        let event = event.event()?;
        let remaining: u64 = event.params.event_data.remaining() as u64;

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

static_plugin!(pub PARSE_INTO_NESTED_TABLE_API = ParseIntoNestedTable);
