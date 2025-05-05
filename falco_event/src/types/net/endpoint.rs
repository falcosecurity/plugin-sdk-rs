use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

pub type SocketAddrV4 = (Ipv4Addr, u16);

impl ToBytes for SocketAddrV4 {
    #[inline]
    fn binary_size(&self) -> usize {
        self.0.binary_size() + self.1.binary_size()
    }

    //noinspection DuplicatedCode
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.0.write(&mut writer)?;
        self.1.write(writer)
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        (Ipv4Addr::from(0), 0)
    }
}

impl FromBytes<'_> for SocketAddrV4 {
    #[inline]
    fn from_bytes(buf: &mut &'_ [u8]) -> Result<Self, FromBytesError> {
        Ok((FromBytes::from_bytes(buf)?, FromBytes::from_bytes(buf)?))
    }
}

pub type SocketAddrV6 = (Ipv6Addr, u16);

impl ToBytes for SocketAddrV6 {
    #[inline]
    fn binary_size(&self) -> usize {
        self.0.binary_size() + self.1.binary_size()
    }

    //noinspection DuplicatedCode
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.0.write(&mut writer)?;
        self.1.write(writer)
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        (Ipv6Addr::from(0), 0)
    }
}

impl FromBytes<'_> for SocketAddrV6 {
    #[inline]
    fn from_bytes(buf: &mut &'_ [u8]) -> Result<Self, FromBytesError> {
        Ok((FromBytes::from_bytes(buf)?, FromBytes::from_bytes(buf)?))
    }
}
