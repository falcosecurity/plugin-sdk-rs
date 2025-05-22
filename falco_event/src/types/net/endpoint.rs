use crate::fields::{FromBytes, FromBytesError, ToBytes};
use crate::types::Port;
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
    fn from_bytes(buf: &mut &'_ [u8]) -> Result<Self, FromBytesError> {
        Ok((FromBytes::from_bytes(buf)?, FromBytes::from_bytes(buf)?))
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
    fn from_bytes(buf: &mut &'_ [u8]) -> Result<Self, FromBytesError> {
        Ok((FromBytes::from_bytes(buf)?, FromBytes::from_bytes(buf)?))
    }
}
