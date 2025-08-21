use crate::plugin_collection::tables::remaining_import_extra_fields::accessors::countdown::get_countdown_by_key;
use crate::plugin_collection::tables::remaining_import_extra_fields::nested_accessors::is_final::get_is_final;
use crate::plugin_collection::tables::remaining_import_extra_fields::RemainingCounterImportTableWithExtraFields;
use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;

struct ExtractNested {
    // reusing the table definition with the #[custom] annotations
    // technically causes the fields to be added again, but we get
    // the existing instances in that case
    remaining_table: RemainingCounterImportTableWithExtraFields,
}

impl Plugin for ExtractNested {
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

impl ExtractNested {
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

impl ExtractPlugin for ExtractNested {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("countdown.is_final", &Self::extract_is_final)];
}

static_plugin!(pub EXTRACT_NESTED_API = ExtractNested);
