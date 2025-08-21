use falco_plugin::tables::export;

pub type RemainingEntryTable = export::Table<u64, RemainingCounter>;

#[derive(export::Entry)]
pub struct RemainingCounter {
    pub remaining: export::Public<u64>,
    pub readonly: export::Readonly<u64>,
}
