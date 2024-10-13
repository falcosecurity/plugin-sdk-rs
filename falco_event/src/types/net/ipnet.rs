use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use std::fmt::Formatter;
use std::io::Write;
use std::net::IpAddr;

/// An IP network
///
/// This is a wrapper around [IpAddr] that makes it a distinct type, suitable for storing
/// IP (v4 or v6) subnets.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_serde_ipv4() {
        let endpoint = super::IpNet(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "\"127.0.0.1\"");

        let endpoint2: super::IpNet = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint, endpoint2);
    }

    #[test]
    fn test_serde_ipv6() {
        let endpoint = super::IpNet(IpAddr::V6(Ipv6Addr::LOCALHOST));

        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "\"::1\"");

        let endpoint2: super::IpNet = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint, endpoint2);
    }
}
