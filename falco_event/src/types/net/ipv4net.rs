use std::fmt::Formatter;
use std::io::Write;
use std::net::Ipv4Addr;

use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;

/// An IPv4 network
///
/// This is a wrapper around [Ipv4Addr] that makes it a distinct type, suitable for storing
/// IPv4 subnets.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
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

impl<F> Format<F> for Ipv4Net {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    #[test]
    fn test_serde_ipv4net() {
        let endpoint = super::Ipv4Net(Ipv4Addr::LOCALHOST);

        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "\"127.0.0.1\"");

        let endpoint2: super::Ipv4Net = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint, endpoint2);
    }
}
