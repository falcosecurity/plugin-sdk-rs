use crate::plugin_collection::tables::remaining_import_extra_fields::accessors::as_string::set_as_string;
use crate::plugin_collection::tables::remaining_import_extra_fields::accessors::countdown::get_countdown;
use crate::plugin_collection::tables::remaining_import_extra_fields::accessors::is_even::set_is_even;
use crate::plugin_collection::tables::remaining_import_extra_fields::accessors::remaining::get_remaining;
use crate::plugin_collection::tables::remaining_import_extra_fields::nested_accessors::count::get_count;
use crate::plugin_collection::tables::remaining_import_extra_fields::nested_accessors::is_final::set_is_final;
use crate::plugin_collection::tables::remaining_import_extra_fields::RemainingCounterImportTableWithExtraFields;
use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::EventInput;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::strings::WriteIntoCString;
use falco_plugin::tables::TablesInput;
use std::ffi::{CStr, CString};
use std::io::Write;
use std::ops::ControlFlow;

struct ParseNestedTableExtraFields {
    remaining_table: RemainingCounterImportTableWithExtraFields,
}

impl Plugin for ParseNestedTableExtraFields {
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

impl ParsePlugin for ParseNestedTableExtraFields {
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

static_plugin!(pub PARSE_NESTED_TABLE_EXTRA_FIELDS_API = ParseNestedTableExtraFields);
