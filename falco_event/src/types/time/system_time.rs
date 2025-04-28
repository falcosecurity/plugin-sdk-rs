use crate::fields::{FromBytes, FromBytesError, ToBytes};
use chrono::Local;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl FromBytes<'_> for SystemTime {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError>
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

#[doc(hidden)]
pub struct SystemTimeFormatter(pub SystemTime);

impl Debug for SystemTimeFormatter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let dt = chrono::DateTime::<Local>::from(self.0);
        f.write_str(&dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false))
    }
}
