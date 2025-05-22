use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

impl FromBytes<'_> for IpAddr {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError> {
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
