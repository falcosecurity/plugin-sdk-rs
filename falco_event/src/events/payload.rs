use crate::events::EventMetadata;
use crate::fields::FromBytesError;
use std::io::Write;
use thiserror::Error;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EventDirection {
    Entry,
    Exit,
}

pub trait EventPayload {
    const ID: u16;
    const NAME: &'static str;

    type LengthType;

    fn direction() -> EventDirection {
        match Self::ID % 2 {
            0 => EventDirection::Entry,
            1 => EventDirection::Exit,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Error)]
pub enum PayloadFromBytesError {
    /// Failed to parse a particular field
    #[error("failed to parse field {0}")]
    NamedField(&'static str, #[source] FromBytesError),

    /// Type mismatch
    #[error("type mismatch")]
    TypeMismatch,

    /// Truncated event
    #[error("truncated event (wanted {wanted}, got {got})")]
    TruncatedEvent { wanted: usize, got: usize },

    /// Unsupported event type
    #[error("unsupported event type {0}")]
    UnsupportedEventType(u16),
}

pub trait PayloadToBytes {
    fn binary_size(&self) -> usize;

    fn write<W: Write>(&self, metadata: &EventMetadata, writer: W) -> std::io::Result<()>;
}
