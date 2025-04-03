use crate::format::OptionFormatter;
use crate::types::SystemTimeFormatter;
use std::fmt::{Debug, Formatter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct EventMetadata {
    pub ts: u64,
    pub tid: i64,
}

impl EventMetadata {
    pub fn timestamp(&self) -> Option<SystemTime> {
        if self.ts == u64::MAX {
            None
        } else {
            Some(UNIX_EPOCH + Duration::from_nanos(self.ts))
        }
    }
}

impl Debug for EventMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} tid={:?}",
            OptionFormatter(self.timestamp().map(SystemTimeFormatter)),
            self.tid
        )
    }
}

impl Default for EventMetadata {
    fn default() -> Self {
        Self {
            ts: u64::MAX,
            tid: -1,
        }
    }
}
