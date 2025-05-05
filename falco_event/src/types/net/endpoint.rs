use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

impl ToBytes for SocketAddrV4 {
    #[inline]
    fn binary_size(&self) -> usize {
        self.ip().binary_size() + self.port().binary_size()
    }

    //noinspection DuplicatedCode
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.ip().write(&mut writer)?;
        self.port().write(writer)
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        SocketAddrV4::new(Ipv4Addr::from(0), 0)
    }
}

impl FromBytes<'_> for SocketAddrV4 {
    #[inline]
    fn from_bytes(buf: &mut &'_ [u8]) -> Result<Self, FromBytesError> {
        Ok(SocketAddrV4::new(
            FromBytes::from_bytes(buf)?,
            FromBytes::from_bytes(buf)?,
        ))
    }
}

impl ToBytes for SocketAddrV6 {
    #[inline]
    fn binary_size(&self) -> usize {
        self.ip().binary_size() + self.port().binary_size()
    }

    //noinspection DuplicatedCode
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.ip().write(&mut writer)?;
        self.port().write(writer)
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        SocketAddrV6::new(Ipv6Addr::from(0), 0, 0, 0)
    }
}

impl FromBytes<'_> for SocketAddrV6 {
    #[inline]
    fn from_bytes(buf: &mut &'_ [u8]) -> Result<Self, FromBytesError> {
        Ok(SocketAddrV6::new(
            FromBytes::from_bytes(buf)?,
            FromBytes::from_bytes(buf)?,
            0,
            0,
        ))
    }
}
