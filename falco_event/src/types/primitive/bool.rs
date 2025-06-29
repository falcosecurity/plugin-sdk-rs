use crate::fields::{FromBytes, FromBytesError, ToBytes};
use crate::types::primitive::bool;
use std::io::Write;

impl FromBytes<'_> for bool {
    #[inline]
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError> {
        let val = u32::from_bytes(buf)?;
        Ok(val != 0)
    }
}

impl ToBytes for bool {
    #[inline]
    fn binary_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    #[inline]
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        let val: u32 = if *self { 1 } else { 0 };
        val.write(writer)
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        0u32
    }
}
