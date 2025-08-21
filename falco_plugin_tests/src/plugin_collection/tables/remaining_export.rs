use falco_plugin::tables::export;

pub type RemainingEntryTable = export::Table<u64, RemainingCounter>;

#[derive(export::Entry)]
pub struct RemainingCounter {
    pub remaining: export::Public<u64>,
    pub readonly: export::Readonly<u64>,
    pub countdown: Box<CountdownTable>,
}

pub type CountdownTable = export::Table<u64, Countdown>;

#[derive(export::Entry)]
pub struct Countdown {
    pub count: export::Public<u64>,
}
