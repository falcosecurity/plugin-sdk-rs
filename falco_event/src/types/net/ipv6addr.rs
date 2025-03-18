use crate::event_derive::{FromBytes, FromBytesError, FromBytesResult, ToBytes};
use crate::format::FormatType;
use crate::types::format::Format;
use std::fmt::Formatter;
use std::io::{Read, Write};
use std::net::Ipv6Addr;

impl FromBytes<'_> for Ipv6Addr {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        if buf.len() < 16 {
            return Err(FromBytesError::InvalidLength);
        }

        let mut out = [0u8; 16];
        buf.read_exact(&mut out)?;
        Ok(out.into())
    }
}

impl ToBytes for Ipv6Addr {
    fn binary_size(&self) -> usize {
        16
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.octets().as_slice())?;
        Ok(())
    }

    fn default_repr() -> impl ToBytes {
        Ipv6Addr::from(0)
    }
}

impl Format for Ipv6Addr {
    fn format(&self, _format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_ipv6_addr() {
        let ip = Ipv6Addr::from_str("2001:4860:4860::8844").unwrap();

        let mut binary = Vec::new();
        ip.write(&mut binary).unwrap();
        assert_eq!(
            binary.as_slice(),
            b"\x20\x01\x48\x60\x48\x60\0\0\0\0\0\0\0\0\x88\x44".as_slice()
        );

        let mut buf = binary.as_slice();
        let ip2 = Ipv6Addr::from_bytes(&mut buf).unwrap();
        assert_eq!(ip, ip2);
    }
}
