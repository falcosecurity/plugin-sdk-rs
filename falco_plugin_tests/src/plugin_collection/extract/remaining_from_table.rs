use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::static_plugin;
use falco_plugin::tables::{export, import, TablesInput};
use std::ffi::CStr;
use std::sync::Arc;

pub type RemainingEntryTable = export::Table<u64, RemainingCounter>;

#[derive(export::Entry)]
pub struct RemainingCounter {
    pub remaining: export::Public<u64>,
}

type RemainingCounterImportTable = import::Table<u64, RemainingCounterImport>;
type RemainingCounterImport = import::Entry<Arc<RemainingCounterImportMetadata>>;

#[derive(import::TableMetadata)]
#[entry_type(RemainingCounterImport)]
struct RemainingCounterImportMetadata {
    remaining: import::Field<u64, RemainingCounterImport>,
}

pub struct ExtractRemainingFromTable {
    remaining_table: RemainingCounterImportTable,
}

impl Plugin for ExtractRemainingFromTable {
    const NAME: &'static CStr = c"extract_remaining_from_table";
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

impl ExtractRemainingFromTable {
    fn extract_remaining(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event_num = req.event.event_number() as u64;

        let entry = self
            .remaining_table
            .get_entry(req.table_reader, &event_num)?;
        let remaining = entry.get_remaining(req.table_reader)?;

        Ok(remaining)
    }
}

impl ExtractPlugin for ExtractRemainingFromTable {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("countdown.remaining", &Self::extract_remaining)];
}

static_plugin!(pub EXTRACT_REMAINING_FROM_TABLE_API = ExtractRemainingFromTable);
