use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::format::FormatType;
use crate::types::format::Format;
use chrono::Local;
use std::fmt::Formatter;
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl FromBytes<'_> for SystemTime {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self>
    where
        Self: Sized,
    {
        let duration = Duration::from_bytes(buf)?;
        Ok(UNIX_EPOCH + duration)
    }
}

impl ToBytes for SystemTime {
    fn binary_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        let duration = self
            .duration_since(UNIX_EPOCH)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        duration.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        0u64
    }
}

impl Format for SystemTime {
    fn format(&self, _format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        let dt = chrono::DateTime::<Local>::from(*self);
        fmt.write_str(&dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_serde_systemtime() {
        let st = SystemTime::UNIX_EPOCH + Duration::from_secs(100 * 86400);
        let json = serde_json::to_string(&st).unwrap();

        assert_eq!(
            json,
            r#"{"secs_since_epoch":8640000,"nanos_since_epoch":0}"#
        );
        let st2: SystemTime = serde_json::from_str(&json).unwrap();
        assert_eq!(st, st2);
    }
}
