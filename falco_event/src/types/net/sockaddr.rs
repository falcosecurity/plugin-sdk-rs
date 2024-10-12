use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::ffi::{PPM_AF_INET, PPM_AF_INET6, PPM_AF_LOCAL, PPM_AF_UNSPEC};
use crate::types::format::Format;
use crate::types::{Borrow, Borrowed, EndpointV4, EndpointV6};
use byteorder::{ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fmt::Formatter;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// A socket address
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SockAddr<'a> {
    /// Unix sockets
    Unix(&'a Path),

    /// IPv4 sockets
    V4(EndpointV4),

    /// IPv6 socket
    V6(EndpointV6),

    /// any other address family is represented as the number (`PPM_AF_*` constant) and the raw data
    Other(u8, &'a [u8]),
}

impl ToBytes for SockAddr<'_> {
    fn binary_size(&self) -> usize {
        match self {
            SockAddr::Unix(p) => 1 + p.binary_size(),
            SockAddr::V4(addr) => 1 + addr.binary_size(),
            SockAddr::V6(addr) => 1 + addr.binary_size(),
            SockAddr::Other(_, buf) => 1 + buf.len(),
        }
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            SockAddr::Unix(p) => {
                writer.write_u8(PPM_AF_LOCAL as u8)?;
                p.write(writer)
            }
            SockAddr::V4(addr) => {
                writer.write_u8(PPM_AF_INET as u8)?;
                addr.write(writer)
            }
            SockAddr::V6(addr) => {
                writer.write_u8(PPM_AF_INET6 as u8)?;
                addr.write(writer)
            }
            SockAddr::Other(af, addr) => {
                writer.write_u8(*af)?;
                ToBytes::write(addr, writer)
            }
        }
    }

    fn default_repr() -> impl ToBytes {
        PPM_AF_UNSPEC as u8
    }
}

impl<'a> FromBytes<'a> for SockAddr<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let variant = buf.read_u8()?;
        match variant as u32 {
            PPM_AF_LOCAL => {
                let path = <OsStr as OsStrExt>::from_bytes(buf);
                *buf = &[];
                Ok(Self::Unix(Path::new(path)))
            }
            PPM_AF_INET => {
                let addr = EndpointV4::from_bytes(buf)?;
                Ok(Self::V4(addr))
            }
            PPM_AF_INET6 => {
                let addr = EndpointV6::from_bytes(buf)?;
                Ok(Self::V6(addr))
            }
            _ => Ok(Self::Other(variant, buf)),
        }
    }
}

impl<F> Format<F> for SockAddr<'_>
where
    EndpointV4: Format<F>,
    EndpointV6: Format<F>,
    for<'a> &'a [u8]: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        match self {
            SockAddr::Unix(u) => {
                let bytes = u.as_os_str().as_bytes();
                fmt.write_str("unix://")?;
                bytes.format(fmt)
            }
            SockAddr::V4(v4) => v4.format(fmt),
            SockAddr::V6(v6) => v6.format(fmt),
            SockAddr::Other(af, raw) => write!(fmt, "<af={}>{:02x?}", af, raw),
        }
    }
}

/// A socket address (owned)
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnedSockAddr {
    /// Unix sockets
    Unix(PathBuf),

    /// IPv4 sockets
    V4(EndpointV4),

    /// IPv6 socket
    V6(EndpointV6),

    /// any other address family is represented as the number (`PPM_AF_*` constant) and the raw data
    Other(u8, Vec<u8>),
}

impl<'a> Borrowed for SockAddr<'a> {
    type Owned = OwnedSockAddr;
}

impl Borrow for OwnedSockAddr {
    type Borrowed<'b> = SockAddr<'b>;

    fn borrow(&self) -> Self::Borrowed<'_> {
        match self {
            OwnedSockAddr::Unix(u) => SockAddr::Unix(u),
            OwnedSockAddr::V4(v4) => SockAddr::V4(*v4),
            OwnedSockAddr::V6(v6) => SockAddr::V6(*v6),
            OwnedSockAddr::Other(af, raw) => SockAddr::Other(*af, raw),
        }
    }
}
