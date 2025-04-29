use std::fmt::{Debug, Formatter};
use std::io::Write;

use crate::ffi::{PPM_AF_INET, PPM_AF_INET6, PPM_AF_LOCAL};
use crate::fields::{FromBytes, FromBytesError, ToBytes};
use crate::types::net::endpoint::{EndpointV4, EndpointV6};
use typed_path::UnixPath;

/// Socket tuple: describing both endpoints of a connection
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub enum SockTuple<'a> {
    /// Unix socket connection
    Unix {
        /// source socket kernel pointer
        source_ptr: u64,
        /// destination socket kernel pointer
        dest_ptr: u64,
        /// filesystem path to the socket
        path: &'a UnixPath,
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
    Other(u8, &'a [u8]),
}

impl Debug for SockTuple<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix {
                source_ptr,
                dest_ptr,
                path,
            } => write!(f, "{:x}->{:x} {}", source_ptr, dest_ptr, path.display()),
            Self::V4 { source, dest } => {
                write!(f, "{}:{} -> {}:{}", source.0, source.1, dest.0, dest.1)
            }
            Self::V6 { source, dest } => {
                write!(f, "[{}]:{} -> [{}]:{}", source.0, source.1, dest.0, dest.1)
            }
            Self::Other(af, buf) => f
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
            Self::Unix {
                source_ptr: source_addr,
                dest_ptr: dest_addr,
                path,
            } => 1 + source_addr.binary_size() + dest_addr.binary_size() + path.binary_size(),
            Self::V4 { source, dest } => 1 + source.binary_size() + dest.binary_size(),
            Self::V6 { source, dest } => 1 + source.binary_size() + dest.binary_size(),
            Self::Other(_, buf) => 1 + buf.len(),
        }
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            Self::Unix {
                source_ptr: source_addr,
                dest_ptr: dest_addr,
                path,
            } => {
                writer.write_all(&[PPM_AF_LOCAL as u8])?;
                source_addr.write(&mut writer)?;
                dest_addr.write(&mut writer)?;
                path.write(writer)
            }
            Self::V4 { source, dest } => {
                writer.write_all(&[PPM_AF_INET as u8])?;
                source.write(&mut writer)?;
                dest.write(writer)
            }
            Self::V6 { source, dest } => {
                writer.write_all(&[PPM_AF_INET6 as u8])?;
                source.write(&mut writer)?;
                dest.write(writer)
            }
            Self::Other(af, buf) => {
                writer.write_all(&[*af])?;
                ToBytes::write(buf, writer)
            }
        }
    }

    fn default_repr() -> impl ToBytes {
        [].as_slice()
    }
}

impl<'a> FromBytes<'a> for SockTuple<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        let variant = buf.split_off_first().ok_or(FromBytesError::InvalidLength)?;

        match *variant as u32 {
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
            _ => Ok(Self::Other(*variant, std::mem::take(buf))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_socktuple_ipv4() {
        let socktuple = SockTuple::V4 {
            source: (Ipv4Addr::from_str("172.31.33.48").unwrap(), 47263),
            dest: (Ipv4Addr::from_str("172.31.0.2").unwrap(), 53),
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
            source: (Ipv6Addr::from_str("2001:4860:4860::8844").unwrap(), 47263),
            dest: (Ipv6Addr::from_str("2001:4860:4860::8800").unwrap(), 53),
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
            panic!("not a unix sock tuple: {socktuple:?}")
        };

        assert_eq!(source_addr, 0);
        assert_eq!(dest_addr, 0xffff98bc4ecf2000);
        assert_eq!(path.as_bytes(), b"/var/run/nscd/socket".as_slice());

        assert_eq!(binary, binary2.as_slice(),);
    }
}
