use crate::fields::{FromBytes, FromBytesError, ToBytes};
use byteorder::{NativeEndian, ReadBytesExt};
use std::io::Write;
use std::time::Duration;

impl FromBytes<'_> for Duration {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError>
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
