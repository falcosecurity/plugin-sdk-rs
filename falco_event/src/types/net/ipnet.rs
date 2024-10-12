use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use std::fmt::Formatter;
use std::io::Write;
use std::net::IpAddr;

/// An IP network
///
/// This is a wrapper around [IpAddr] that makes it a distinct type, suitable for storing
/// IP (v4 or v6) subnets.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct IpNet(pub IpAddr);

impl FromBytes<'_> for IpNet {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
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

impl<F> Format<F> for IpNet
where
    IpAddr: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        self.0.format(fmt)
    }
}
