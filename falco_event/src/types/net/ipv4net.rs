use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::net::Ipv4Addr;

/// An IPv4 network
///
/// This is a wrapper around [Ipv4Addr] that makes it a distinct type, suitable for storing
/// IPv4 subnets.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Ipv4Net(pub Ipv4Addr);

impl FromBytes<'_> for Ipv4Net {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        Ok(Self(Ipv4Addr::from_bytes(buf)?))
    }
}

impl ToBytes for Ipv4Net {
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        Ipv4Addr::default_repr()
    }
}

impl Debug for Ipv4Net {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}
