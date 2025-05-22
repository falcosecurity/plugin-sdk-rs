use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::net::Ipv6Addr;

/// An IPv6 network
///
/// This is a wrapper around [Ipv6Addr] that makes it a distinct type, suitable for storing
/// IPv6 subnets.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Ipv6Net(pub Ipv6Addr);

impl FromBytes<'_> for Ipv6Net {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError> {
        Ok(Self(Ipv6Addr::from_bytes(buf)?))
    }
}

impl ToBytes for Ipv6Net {
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        Ipv6Addr::default_repr()
    }
}

impl Debug for Ipv6Net {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}
