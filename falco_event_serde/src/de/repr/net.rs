use crate::de::repr::{Repr, StaticRepr, TaggedRepr};
use bstr::ByteSlice;
use falco_event::ffi::{PPM_AF_INET, PPM_AF_INET6, PPM_AF_UNIX};
use falco_event::fields::types;
use serde::{Deserialize, Deserializer};
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

macro_rules! impl_deserialize_from_ipaddr {
    ($underlying:ty => $tag:ty) => {
        impl<'de> Deserialize<'de> for TaggedRepr<$tag> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let ip_addr: $underlying = Deserialize::deserialize(deserializer)?;
                Ok(Self {
                    repr: Repr::Static(StaticRepr::from(ip_addr.to_bits().to_be_bytes())),
                    tag: PhantomData,
                })
            }
        }
    };
}

impl_deserialize_from_ipaddr!(Ipv4Addr => types::PT_IPV4ADDR);
impl_deserialize_from_ipaddr!(Ipv4Addr => types::PT_IPV4NET);
impl_deserialize_from_ipaddr!(Ipv6Addr => types::PT_IPV6ADDR);
impl_deserialize_from_ipaddr!(Ipv6Addr => types::PT_IPV6NET);

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_IPADDR> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ip_addr: IpAddr = Deserialize::deserialize(deserializer)?;
        match ip_addr {
            IpAddr::V4(addr) => Ok(Self {
                repr: Repr::Static(StaticRepr::from(addr.to_bits().to_be_bytes())),
                tag: PhantomData,
            }),
            IpAddr::V6(addr) => Ok(Self {
                repr: Repr::Static(StaticRepr::from(addr.to_bits().to_be_bytes())),
                tag: PhantomData,
            }),
        }
    }
}

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_IPNET> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addr: TaggedRepr<types::PT_IPADDR> = Deserialize::deserialize(deserializer)?;
        Ok(Self {
            repr: addr.repr,
            tag: PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_SOCKADDR<'_>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum SockAddr {
            Unix(bstr::BString),
            V4(Ipv4Addr, u16),
            V6(Ipv6Addr, u16),
            Other(u8, bstr::BString),
        }

        let addr = Deserialize::deserialize(deserializer)?;
        let repr = match addr {
            SockAddr::Unix(path) => {
                let mut bytes = Vec::new();
                bytes.push(PPM_AF_UNIX as u8);
                bytes.extend_from_slice(path.as_bytes());
                bytes.push(0u8);
                StaticRepr::Vec(bytes)
            }
            SockAddr::V4(addr, port) => {
                let mut bytes = [0u8; 7];
                bytes[0] = PPM_AF_INET as u8;
                bytes[1..5].copy_from_slice(&addr.to_bits().to_be_bytes());
                bytes[5..].copy_from_slice(&port.to_ne_bytes());
                StaticRepr::from(bytes)
            }
            SockAddr::V6(addr, port) => {
                let mut bytes = [0u8; 19];
                bytes[0] = PPM_AF_INET6 as u8;
                bytes[1..17].copy_from_slice(&addr.to_bits().to_be_bytes());
                bytes[17..].copy_from_slice(&port.to_ne_bytes());
                StaticRepr::from(bytes)
            }
            SockAddr::Other(af, addr) => {
                let mut bytes = Vec::new();
                bytes.push(af);
                bytes.extend_from_slice(addr.as_slice());
                StaticRepr::Vec(bytes)
            }
        };

        Ok(Self {
            repr: Repr::Static(repr),
            tag: PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_SOCKTUPLE<'_>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum SockTuple {
            Unix(u64, u64, bstr::BString),
            V4(Ipv4Addr, u16, Ipv4Addr, u16),
            V6(Ipv6Addr, u16, Ipv6Addr, u16),
            Other(u8, bstr::BString),
        }

        let addr = Deserialize::deserialize(deserializer)?;
        let repr = match addr {
            SockTuple::Unix(src, dst, path) => {
                let mut bytes = Vec::new();
                bytes.push(PPM_AF_UNIX as u8);
                bytes.extend_from_slice(&src.to_ne_bytes());
                bytes.extend_from_slice(&dst.to_ne_bytes());
                bytes.extend_from_slice(path.as_slice());
                bytes.push(0u8);
                StaticRepr::Vec(bytes)
            }
            SockTuple::V4(saddr, sport, daddr, dport) => {
                let mut bytes = [0u8; 13];
                bytes[0] = PPM_AF_INET as u8;
                bytes[1..5].copy_from_slice(&saddr.to_bits().to_be_bytes());
                bytes[5..7].copy_from_slice(&sport.to_ne_bytes());
                bytes[7..11].copy_from_slice(&daddr.to_bits().to_be_bytes());
                bytes[11..].copy_from_slice(&dport.to_ne_bytes());
                StaticRepr::from(bytes)
            }
            SockTuple::V6(saddr, sport, daddr, dport) => {
                let mut bytes = Vec::new();
                bytes.push(PPM_AF_INET6 as u8);
                bytes.extend_from_slice(&saddr.to_bits().to_be_bytes());
                bytes.extend_from_slice(&sport.to_ne_bytes());
                bytes.extend_from_slice(&daddr.to_bits().to_be_bytes());
                bytes.extend_from_slice(&dport.to_ne_bytes());
                StaticRepr::Vec(bytes)
            }
            SockTuple::Other(af, addr) => {
                let mut bytes = Vec::new();
                bytes.push(af);
                bytes.extend_from_slice(addr.as_slice());
                StaticRepr::Vec(bytes)
            }
        };

        Ok(Self {
            repr: Repr::Static(repr),
            tag: PhantomData,
        })
    }
}
