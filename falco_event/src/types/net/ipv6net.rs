use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::net::Ipv6Addr;

/// An IPv6 network
///
/// This is a wrapper around [Ipv6Addr] that makes it a distinct type, suitable for storing
/// IPv6 subnets.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Ipv6Net(pub Ipv6Addr);

impl FromBytes<'_> for Ipv6Net {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
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

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use std::net::Ipv6Addr;

    #[test]
    fn test_serde_ipv6net() {
        let endpoint = super::Ipv6Net(Ipv6Addr::LOCALHOST);

        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "\"::1\"");

        let endpoint2: super::Ipv6Net = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint, endpoint2);
    }
}
