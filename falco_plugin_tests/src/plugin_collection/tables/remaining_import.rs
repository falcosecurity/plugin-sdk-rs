use falco_plugin::tables::import;
use std::sync::Arc;

pub type RemainingCounterImportTable = import::Table<u64, RemainingCounterImport>;
pub type RemainingCounterImport = import::Entry<Arc<RemainingCounterImportMetadata>>;

#[derive(import::TableMetadata)]
#[entry_type(RemainingCounterImport)]
#[accessors_mod(accessors)]
pub struct RemainingCounterImportMetadata {
    remaining: import::Field<u64, RemainingCounterImport>,
}
