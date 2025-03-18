use crate::event_derive::Format;
use crate::format::FormatType;
use std::fmt::{Debug, Formatter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
        f.debug_struct("EventMetadata")
            .field("ts", &self.timestamp())
            .field("tid", &self.tid)
            .finish()
    }
}

impl Format for EventMetadata {
    fn format(&self, format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        self.timestamp().format(format_type, fmt)?;
        fmt.write_str(" tid=")?;
        self.tid.format(format_type, fmt)
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
