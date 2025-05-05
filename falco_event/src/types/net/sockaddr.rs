use crate::ffi::{PPM_AF_INET, PPM_AF_INET6, PPM_AF_LOCAL, PPM_AF_UNSPEC};
use crate::fields::{FromBytes, FromBytesError, ToBytes};
use crate::types::SocketAddrV6;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::net::SocketAddrV4;
use typed_path::UnixPath;

/// A socket address
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SockAddr<'a> {
    /// Unix sockets
    Unix(&'a UnixPath),

    /// IPv4 sockets
    V4(SocketAddrV4),

    /// IPv6 socket
    V6(SocketAddrV6),

    /// any other address family is represented as the number (`PPM_AF_*` constant) and the raw data
    Other(u8, &'a [u8]),
}

impl ToBytes for SockAddr<'_> {
    fn binary_size(&self) -> usize {
        match self {
            Self::Unix(p) => 1 + p.binary_size(),
            Self::V4(addr) => 1 + addr.binary_size(),
            Self::V6(addr) => 1 + addr.binary_size(),
            Self::Other(_, buf) => 1 + buf.len(),
        }
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            Self::Unix(p) => {
                writer.write_all(&[PPM_AF_LOCAL as u8])?;
                p.write(writer)
            }
            Self::V4(addr) => {
                writer.write_all(&[PPM_AF_INET as u8])?;
                addr.write(writer)
            }
            Self::V6(addr) => {
                writer.write_all(&[PPM_AF_INET6 as u8])?;
                addr.write(writer)
            }
            Self::Other(af, addr) => {
                writer.write_all(&[*af])?;
                ToBytes::write(addr, writer)
            }
        }
    }

    fn default_repr() -> impl ToBytes {
        PPM_AF_UNSPEC as u8
    }
}

impl<'a> FromBytes<'a> for SockAddr<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        let variant = buf.split_off_first().ok_or(FromBytesError::InvalidLength)?;

        match *variant as u32 {
            PPM_AF_LOCAL => {
                let path: &UnixPath = FromBytes::from_bytes(buf)?;
                Ok(Self::Unix(path))
            }
            PPM_AF_INET => {
                let addr = SocketAddrV4::from_bytes(buf)?;
                Ok(Self::V4(addr))
            }
            PPM_AF_INET6 => {
                let addr = SocketAddrV6::from_bytes(buf)?;
                Ok(Self::V6(addr))
            }
            _ => Ok(Self::Other(*variant, std::mem::take(buf))),
        }
    }
}

impl Debug for SockAddr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SockAddr::Unix(u) => write!(f, "unix://{}", u.display()),
            SockAddr::V4(v4) => write!(f, "{v4}"),
            SockAddr::V6(v6) => write!(f, "[{}]:{}", v6.0, v6.1),
            SockAddr::Other(af, raw) => write!(f, "<af={af}>{raw:02x?}"),
        }
    }
}
