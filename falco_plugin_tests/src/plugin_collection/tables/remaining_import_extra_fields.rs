use falco_plugin::tables::import;
use std::ffi::CStr;
use std::sync::Arc;

// now, redefine the table but add some extra fields
pub type RemainingCounterImportTableWithExtraFields =
    import::Table<u64, RemainingCounterImportWithExtraFields>;
pub type RemainingCounterImportWithExtraFields =
    import::Entry<Arc<RemainingCounterImportMetadataWithExtraFields>>;

#[derive(import::TableMetadata)]
#[entry_type(RemainingCounterImportWithExtraFields)]
#[accessors_mod(accessors)]
pub struct RemainingCounterImportMetadataWithExtraFields {
    remaining: import::Field<u64, RemainingCounterImportWithExtraFields>,

    #[custom]
    is_even: import::Field<import::Bool, RemainingCounterImportWithExtraFields>,
    #[custom]
    as_string: import::Field<CStr, RemainingCounterImportWithExtraFields>,
}
