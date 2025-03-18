use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::format::FormatType;
use crate::types::format::Format;
use crate::types::BorrowDeref;
use byteorder::{NativeEndian, ReadBytesExt};
use std::fmt::Formatter;
use std::io::Write;
use std::time::Duration;

impl FromBytes<'_> for Duration {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self>
    where
        Self: Sized,
    {
        Ok(buf.read_u64::<NativeEndian>().map(Self::from_nanos)?)
    }
}

impl ToBytes for Duration {
    fn binary_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        (self.as_nanos() as u64).write(writer)
    }

    fn default_repr() -> impl ToBytes {
        0u64
    }
}

impl Format for Duration {
    fn format(&self, _format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, fmt)
    }
}

impl BorrowDeref for Duration {
    type Target<'a> = Duration;

    fn borrow_deref(&self) -> Self::Target<'_> {
        *self
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn test_serde_duration() {
        let duration = Duration::from_nanos(1_234_567_890);
        let json = serde_json::to_string(&duration).unwrap();
        assert_eq!(json, r#"{"secs":1,"nanos":234567890}"#);

        let duration2: Duration = serde_json::from_str(&json).unwrap();
        assert_eq!(duration, duration2);
    }
}
