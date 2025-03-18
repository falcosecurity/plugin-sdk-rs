use crate::event_derive::{FromBytes, FromBytesError, FromBytesResult, ToBytes};
use crate::format::FormatType;
use crate::types::format::Format;
use std::fmt::Formatter;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

impl FromBytes<'_> for IpAddr {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        match buf.len() {
            4 => Ok(IpAddr::V4(Ipv4Addr::from_bytes(buf)?)),
            16 => Ok(IpAddr::V6(Ipv6Addr::from_bytes(buf)?)),
            _ => Err(FromBytesError::InvalidLength),
        }
    }
}

impl ToBytes for IpAddr {
    fn binary_size(&self) -> usize {
        match self {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        match self {
            IpAddr::V4(v4) => v4.write(writer),
            IpAddr::V6(v6) => v6.write(writer),
        }
    }

    fn default_repr() -> impl ToBytes {
        IpAddr::V4(Ipv4Addr::from(0))
    }
}

impl Format for IpAddr {
    fn format(&self, _format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_serde_ipv4() {
        let endpoint = Ipv4Addr::LOCALHOST;

        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "\"127.0.0.1\"");

        let endpoint2: Ipv4Addr = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint, endpoint2);
    }

    #[test]
    fn test_serde_ipv6() {
        let endpoint = Ipv6Addr::LOCALHOST;

        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "\"::1\"");

        let endpoint2: Ipv6Addr = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint, endpoint2);
    }
}
