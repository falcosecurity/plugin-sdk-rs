use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::Port;
use std::fmt::Formatter;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

pub type EndpointV4 = (Ipv4Addr, Port);

impl ToBytes for EndpointV4 {
    fn binary_size(&self) -> usize {
        self.0.binary_size() + self.1.binary_size()
    }

    //noinspection DuplicatedCode
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.0.write(&mut writer)?;
        self.1.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        (Ipv4Addr::from(0), Port(0))
    }
}

impl FromBytes<'_> for EndpointV4 {
    fn from_bytes(buf: &mut &'_ [u8]) -> FromBytesResult<Self> {
        Ok((FromBytes::from_bytes(buf)?, FromBytes::from_bytes(buf)?))
    }
}

impl<F> Format<F> for EndpointV4 {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "{}:{}", self.0, self.1 .0)
    }
}

pub type EndpointV6 = (Ipv6Addr, Port);

impl ToBytes for EndpointV6 {
    fn binary_size(&self) -> usize {
        self.0.binary_size() + self.1.binary_size()
    }

    //noinspection DuplicatedCode
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.0.write(&mut writer)?;
        self.1.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        (Ipv6Addr::from(0), Port(0))
    }
}

impl FromBytes<'_> for EndpointV6 {
    fn from_bytes(buf: &mut &'_ [u8]) -> FromBytesResult<Self> {
        Ok((FromBytes::from_bytes(buf)?, FromBytes::from_bytes(buf)?))
    }
}

impl<F> Format<F> for EndpointV6 {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "[{}]:{}", self.0, self.1 .0)
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::Port;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_serde_endpoint_v4() {
        let endpoint = (Ipv4Addr::LOCALHOST, Port(8080));

        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "[\"127.0.0.1\",8080]");

        let endpoint2: super::EndpointV4 = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint, endpoint2);
    }

    #[test]
    fn test_serde_endpoint_v6() {
        let endpoint = (Ipv6Addr::LOCALHOST, Port(8080));

        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "[\"::1\",8080]");

        let endpoint2: super::EndpointV6 = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint, endpoint2);
    }
}
