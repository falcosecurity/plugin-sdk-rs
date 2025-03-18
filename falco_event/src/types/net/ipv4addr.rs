use std::fmt::Formatter;
use std::io::Write;
use std::net::Ipv4Addr;

use byteorder::{NetworkEndian, ReadBytesExt};

use crate::fields::{FromBytes, FromBytesResult, ToBytes};
use crate::format::FormatType;
use crate::types::format::Format;

impl FromBytes<'_> for Ipv4Addr {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        let bytes = buf.read_u32::<NetworkEndian>()?;
        Ok(bytes.into())
    }
}

impl ToBytes for Ipv4Addr {
    fn binary_size(&self) -> usize {
        4
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.octets().as_slice().write(writer)
    }

    fn default_repr() -> impl ToBytes {
        Ipv4Addr::from(0)
    }
}

impl Format for Ipv4Addr {
    fn format(&self, _format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_ipv4_addr() {
        let ip = Ipv4Addr::from_str("169.254.169.123").unwrap();

        let mut binary = Vec::new();
        ip.write(&mut binary).unwrap();
        assert_eq!(binary.as_slice(), b"\xa9\xfe\xa9\x7b".as_slice(),);

        let mut buf = binary.as_slice();
        let ip2 = Ipv4Addr::from_bytes(&mut buf).unwrap();
        assert_eq!(ip, ip2);
    }
}
