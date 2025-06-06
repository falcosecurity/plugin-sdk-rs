use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::ffi::{PPM_AF_INET, PPM_AF_INET6, PPM_AF_LOCAL, PPM_AF_UNSPEC};
use crate::types::{Borrow, EndpointV4, EndpointV6};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use typed_path::{UnixPath, UnixPathBuf};

/// A socket address
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum SockAddr<'a> {
    /// Unix sockets
    Unix(
        #[cfg_attr(feature = "serde", serde(with = "crate::types::serde::unix_path"))] &'a UnixPath,
    ),

    /// IPv4 sockets
    V4(EndpointV4),

    /// IPv6 socket
    V6(EndpointV6),

    /// any other address family is represented as the number (`PPM_AF_*` constant) and the raw data
    Other(
        u8,
        #[cfg_attr(feature = "serde", serde(with = "crate::types::serde::bytebuf"))] &'a [u8],
    ),
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
                let path: &UnixPath = FromBytes::from_bytes(buf)?;
                Ok(Self::Unix(path))
            }
            PPM_AF_INET => {
                let addr = EndpointV4::from_bytes(buf)?;
                Ok(Self::V4(addr))
            }
            PPM_AF_INET6 => {
                let addr = EndpointV6::from_bytes(buf)?;
                Ok(Self::V6(addr))
            }
            _ => Ok(Self::Other(variant, std::mem::take(buf))),
        }
    }
}

impl Debug for SockAddr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SockAddr::Unix(u) => write!(f, "unix://{}", u.display()),
            SockAddr::V4(v4) => write!(f, "{}:{}", v4.0, v4.1 .0),
            SockAddr::V6(v6) => write!(f, "[{}]:{}", v6.0, v6.1 .0),
            SockAddr::Other(af, raw) => write!(f, "<af={}>{:02x?}", af, raw),
        }
    }
}

/// A socket address (owned)
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum OwnedSockAddr {
    /// Unix sockets
    Unix(
        #[cfg_attr(feature = "serde", serde(with = "crate::types::serde::unix_path"))] UnixPathBuf,
    ),

    /// IPv4 sockets
    V4(EndpointV4),

    /// IPv6 socket
    V6(EndpointV6),

    /// any other address family is represented as the number (`PPM_AF_*` constant) and the raw data
    Other(
        u8,
        #[cfg_attr(feature = "serde", serde(with = "crate::types::serde::bytebuf"))] Vec<u8>,
    ),
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

impl Debug for OwnedSockAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OwnedSockAddr::Unix(u) => write!(f, "unix://{}", u.display()),
            OwnedSockAddr::V4(v4) => write!(f, "{}:{}", v4.0, v4.1 .0),
            OwnedSockAddr::V6(v6) => write!(f, "[{}]:{}", v6.0, v6.1 .0),
            OwnedSockAddr::Other(af, raw) => write!(f, "<af={}>{:02x?}", af, raw),
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use crate::types::{OwnedSockAddr, Port, SockAddr};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use typed_path::UnixPath;

    #[test]
    fn test_serde_sockaddr_unix() {
        let path = UnixPath::new("/path/to/unix");
        let sockaddr = SockAddr::Unix(path);

        let json = serde_json::to_string(&sockaddr).unwrap();
        assert_eq!(json, r#"{"unix":"/path/to/unix"}"#);
        let sockaddr2: OwnedSockAddr = serde_json::from_str(&json).unwrap();

        let json2 = serde_json::to_string(&sockaddr2).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_serde_sockaddr_v4() {
        let sockaddr = SockAddr::V4((Ipv4Addr::LOCALHOST, Port(8080)));

        let json = serde_json::to_string(&sockaddr).unwrap();
        assert_eq!(json, r#"{"v4":["127.0.0.1",8080]}"#);
        let sockaddr2: OwnedSockAddr = serde_json::from_str(&json).unwrap();

        let json2 = serde_json::to_string(&sockaddr2).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_serde_sockaddr_v6() {
        let sockaddr = SockAddr::V6((Ipv6Addr::LOCALHOST, Port(8080)));

        let json = serde_json::to_string(&sockaddr).unwrap();
        assert_eq!(json, r#"{"v6":["::1",8080]}"#);
        let sockaddr2: OwnedSockAddr = serde_json::from_str(&json).unwrap();

        let json2 = serde_json::to_string(&sockaddr2).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_serde_sockaddr_other() {
        let sockaddr = SockAddr::Other(123, b"foo");

        let json = serde_json::to_string(&sockaddr).unwrap();
        assert_eq!(json, r#"{"other":[123,"foo"]}"#);
        let sockaddr2: OwnedSockAddr = serde_json::from_str(&json).unwrap();

        let json2 = serde_json::to_string(&sockaddr2).unwrap();
        assert_eq!(json, json2);
    }
}
