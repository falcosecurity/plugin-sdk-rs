use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::{BorrowDeref, Borrowed};
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

impl<F> Format<F> for Duration {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, fmt)
    }
}

impl Borrowed for Duration {
    type Owned = Self;
}

impl BorrowDeref for Duration {
    type Target<'a> = Duration;

    fn borrow_deref(&self) -> Self::Target<'_> {
        *self
    }
}
