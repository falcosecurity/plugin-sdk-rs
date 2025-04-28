use crate::fields::FromBytes;
use crate::fields::{FromBytesError, ToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::net::IpAddr;

/// An IP network
///
/// This is a wrapper around [IpAddr] that makes it a distinct type, suitable for storing
/// IP (v4 or v6) subnets.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct IpNet(pub IpAddr);

impl FromBytes<'_> for IpNet {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError> {
        Ok(Self(IpAddr::from_bytes(buf)?))
    }
}

impl ToBytes for IpNet {
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        IpAddr::default_repr()
    }
}

impl Debug for IpNet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}
