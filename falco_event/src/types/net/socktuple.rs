use std::fmt::{Debug, Display, Formatter};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::ffi::{PPM_AF_INET, PPM_AF_INET6, PPM_AF_LOCAL};
use crate::fields::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::net::endpoint::{EndpointV4, EndpointV6};
use crate::types::{Borrow, Borrowed};
use byteorder::{ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};

/// Socket tuple: describing both endpoints of a connection
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SockTuple<'a> {
    /// Unix socket connection
    Unix {
        /// source socket kernel pointer
        source_ptr: u64,
        /// destination socket kernel pointer
        dest_ptr: u64,
        /// filesystem path to the socket
        path: &'a Path,
    },

    /// IPv4 connection
    V4 {
        /// source address and port
        source: EndpointV4,
        /// destination address and port
        dest: EndpointV4,
    },

    /// IPv6 connection
    V6 {
        /// source address and port
        source: EndpointV6,
        /// destination address and port
        dest: EndpointV6,
    },

    /// Unknown/other socket family: `PPM_AF_*` id and a raw byte buffer
    Other(u8, #[serde(with = "crate::types::serde::bytebuf")] &'a [u8]),
}

impl Display for SockTuple<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SockTuple::Unix {
                source_ptr,
                dest_ptr,
                path,
            } => write!(f, "{:x}->{:x} {}", source_ptr, dest_ptr, path.display()),
            SockTuple::V4 { source, dest } => write!(
                f,
                "{}:{} -> {}:{}",
                source.0, source.1 .0, dest.0, dest.1 .0
            ),
            SockTuple::V6 { source, dest } => write!(
                f,
                "[{}]:{} -> [{}]:{}",
                source.0, source.1 .0, dest.0, dest.1 .0
            ),
            SockTuple::Other(af, buf) => f
                .debug_struct("SockTuple")
                .field("af", &af)
                .field("addr", buf)
                .finish(),
        }
    }
}

impl ToBytes for SockTuple<'_> {
    fn binary_size(&self) -> usize {
        match self {
            SockTuple::Unix {
                source_ptr: source_addr,
                dest_ptr: dest_addr,
                path,
            } => 1 + source_addr.binary_size() + dest_addr.binary_size() + path.binary_size(),
            SockTuple::V4 { source, dest } => 1 + source.binary_size() + dest.binary_size(),
            SockTuple::V6 { source, dest } => 1 + source.binary_size() + dest.binary_size(),
            SockTuple::Other(_, buf) => 1 + buf.len(),
        }
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            SockTuple::Unix {
                source_ptr: source_addr,
                dest_ptr: dest_addr,
                path,
            } => {
                writer.write_u8(PPM_AF_LOCAL as u8)?;
                source_addr.write(&mut writer)?;
                dest_addr.write(&mut writer)?;
                path.write(writer)
            }
            SockTuple::V4 { source, dest } => {
                writer.write_u8(PPM_AF_INET as u8)?;
                source.write(&mut writer)?;
                dest.write(writer)
            }
            SockTuple::V6 { source, dest } => {
                writer.write_u8(PPM_AF_INET6 as u8)?;
                source.write(&mut writer)?;
                dest.write(writer)
            }
            SockTuple::Other(af, buf) => {
                writer.write_u8(*af)?;
                ToBytes::write(buf, writer)
            }
        }
    }

    fn default_repr() -> impl ToBytes {
        [].as_slice()
    }
}

impl<'a> FromBytes<'a> for SockTuple<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let variant = buf.read_u8()?;
        match variant as u32 {
            PPM_AF_LOCAL => Ok(Self::Unix {
                source_ptr: FromBytes::from_bytes(buf)?,
                dest_ptr: FromBytes::from_bytes(buf)?,
                path: FromBytes::from_bytes(buf)?,
            }),
            PPM_AF_INET => Ok(Self::V4 {
                source: FromBytes::from_bytes(buf)?,
                dest: FromBytes::from_bytes(buf)?,
            }),
            PPM_AF_INET6 => Ok(Self::V6 {
                source: FromBytes::from_bytes(buf)?,
                dest: FromBytes::from_bytes(buf)?,
            }),
            _ => Ok(Self::Other(variant, buf)),
        }
    }
}

impl<F> Format<F> for SockTuple<'_>
where
    for<'a> &'a Path: Format<F>,
    EndpointV4: Format<F>,
    EndpointV6: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        match self {
            SockTuple::Unix {
                source_ptr,
                dest_ptr,
                path,
            } => {
                write!(fmt, "<{:#016x}->{:#016x}>unix://", source_ptr, dest_ptr)?;
                path.format(fmt)
            }
            SockTuple::V4 { source, dest } => {
                source.format(fmt)?;
                fmt.write_str("->")?;
                dest.format(fmt)
            }
            SockTuple::V6 { source, dest } => {
                source.format(fmt)?;
                fmt.write_str("->")?;
                dest.format(fmt)
            }
            SockTuple::Other(af, raw) => write!(fmt, "<af={}>{:02x?}", af, raw),
        }
    }
}

/// Socket tuple: describing both endpoints of a connection (owned)
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnedSockTuple {
    /// Unix socket connection
    Unix {
        /// source socket kernel pointer
        source_ptr: u64,
        /// destination socket kernel pointer
        dest_ptr: u64,
        /// filesystem path to the socket
        path: PathBuf,
    },

    /// IPv4 connection
    V4 {
        /// source address and port
        source: EndpointV4,
        /// destination address and port
        dest: EndpointV4,
    },

    /// IPv6 connection
    V6 {
        /// source address and port
        source: EndpointV6,
        /// destination address and port
        dest: EndpointV6,
    },

    /// Unknown/other socket family: `PPM_AF_*` id and a raw byte buffer
    Other(u8, #[serde(with = "crate::types::serde::bytebuf")] Vec<u8>),
}

impl<'a> Borrowed for SockTuple<'a> {
    type Owned = OwnedSockTuple;
}

impl Borrow for OwnedSockTuple {
    type Borrowed<'b> = SockTuple<'b>;

    fn borrow(&self) -> Self::Borrowed<'_> {
        match self {
            OwnedSockTuple::Unix {
                source_ptr,
                dest_ptr,
                path,
            } => SockTuple::Unix {
                source_ptr: *source_ptr,
                dest_ptr: *dest_ptr,
                path: path.as_path(),
            },
            OwnedSockTuple::V4 { source, dest } => SockTuple::V4 {
                source: *source,
                dest: *dest,
            },
            OwnedSockTuple::V6 { source, dest } => SockTuple::V6 {
                source: *source,
                dest: *dest,
            },
            OwnedSockTuple::Other(af, raw) => SockTuple::Other(*af, raw.as_slice()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Port;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::ffi::OsStrExt;
    use std::str::FromStr;

    #[test]
    fn test_socktuple_ipv4() {
        let socktuple = SockTuple::V4 {
            source: (Ipv4Addr::from_str("172.31.33.48").unwrap(), Port(47263)),
            dest: (Ipv4Addr::from_str("172.31.0.2").unwrap(), Port(53)),
        };

        dbg!(&socktuple);

        let mut binary = Vec::new();
        socktuple.write(&mut binary).unwrap();

        assert_eq!(
            binary.as_slice(),
            b"\x02\xac\x1f!0\x9f\xb8\xac\x1f\x00\x025\x00".as_slice()
        );

        let mut buf = binary.as_slice();
        let socktuple2 = <SockTuple>::from_bytes(&mut buf).unwrap();
        assert_eq!(socktuple, socktuple2)
    }

    #[test]
    fn test_socktuple_ipv6() {
        let socktuple = SockTuple::V6 {
            source: (
                Ipv6Addr::from_str("2001:4860:4860::8844").unwrap(),
                Port(47263),
            ),
            dest: (
                Ipv6Addr::from_str("2001:4860:4860::8800").unwrap(),
                Port(53),
            ),
        };

        dbg!(&socktuple);

        let mut binary = Vec::new();
        socktuple.write(&mut binary).unwrap();

        assert_eq!(
            binary.as_slice(),
            b"\x0a\x20\x01\x48\x60\x48\x60\0\0\0\0\0\0\0\0\x88\x44\x9f\xb8\x20\x01\x48\x60\x48\x60\0\0\0\0\0\0\0\0\x88\x00\x35\x00".as_slice()
        );

        let mut buf = binary.as_slice();
        let socktuple2 = <SockTuple>::from_bytes(&mut buf).unwrap();
        assert_eq!(socktuple, socktuple2)
    }

    #[test]
    fn test_socktuple_unix() {
        let binary = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00 \xcfN\xbc\x98\xff\xff/var/run/nscd/socket\x00".as_slice();
        let mut buf = binary;

        let socktuple = <SockTuple>::from_bytes(&mut buf).unwrap();
        dbg!(&socktuple);

        let mut binary2 = Vec::new();
        socktuple.write(&mut binary2).unwrap();

        let SockTuple::Unix {
            source_ptr: source_addr,
            dest_ptr: dest_addr,
            path,
        } = socktuple
        else {
            panic!("not a unix sock tuple: {:?}", socktuple)
        };

        assert_eq!(source_addr, 0);
        assert_eq!(dest_addr, 0xffff98bc4ecf2000);
        assert_eq!(
            path.as_os_str().as_bytes(),
            b"/var/run/nscd/socket".as_slice()
        );

        assert_eq!(binary, binary2.as_slice(),);
    }

    #[test]
    fn test_serde_socktuple_unix() {
        let path = Path::new("/path/to/unix");
        let sockaddr = SockTuple::Unix {
            source_ptr: 1,
            dest_ptr: 2,
            path,
        };

        let json = serde_json::to_string(&sockaddr).unwrap();
        assert_eq!(
            json,
            r#"{"unix":{"source_ptr":1,"dest_ptr":2,"path":"/path/to/unix"}}"#
        );
        let sockaddr2: OwnedSockTuple = serde_json::from_str(&json).unwrap();

        let json2 = serde_json::to_string(&sockaddr2).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_serde_socktuple_v4() {
        let sockaddr = SockTuple::V4 {
            source: (Ipv4Addr::LOCALHOST, Port(8080)),
            dest: (Ipv4Addr::new(192, 168, 0, 1), Port(8081)),
        };

        let json = serde_json::to_string(&sockaddr).unwrap();
        assert_eq!(
            json,
            r#"{"v4":{"source":["127.0.0.1",8080],"dest":["192.168.0.1",8081]}}"#
        );
        let sockaddr2: OwnedSockTuple = serde_json::from_str(&json).unwrap();

        let json2 = serde_json::to_string(&sockaddr2).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_serde_sockaddr_v6() {
        let sockaddr = SockTuple::V6 {
            source: (Ipv6Addr::LOCALHOST, Port(8080)),
            dest: (Ipv6Addr::from_str("::2").unwrap(), Port(8081)),
        };

        let json = serde_json::to_string(&sockaddr).unwrap();
        assert_eq!(
            json,
            r#"{"v6":{"source":["::1",8080],"dest":["::2",8081]}}"#
        );
        let sockaddr2: OwnedSockTuple = serde_json::from_str(&json).unwrap();

        let json2 = serde_json::to_string(&sockaddr2).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_serde_socktuple_other() {
        let sockaddr = SockTuple::Other(123, b"foo");

        let json = serde_json::to_string(&sockaddr).unwrap();
        assert_eq!(json, r#"{"other":[123,"foo"]}"#);
        let sockaddr2: OwnedSockTuple = serde_json::from_str(&json).unwrap();

        let json2 = serde_json::to_string(&sockaddr2).unwrap();
        assert_eq!(json, json2);
    }
}
