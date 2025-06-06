mod dynamic_params;
mod fd_list;
mod flags;
mod integers;
mod net;
mod newtypes;
mod strings;
mod time;

use falco_event::fields::ToBytes;
use serde::{Deserialize, Deserializer};
use std::io::Write;
use std::marker::PhantomData;

#[derive(Debug, Deserialize)]
pub enum StaticRepr {
    None,
    U8([u8; 1]),
    U16([u8; 2]),
    U32([u8; 4]),
    U64([u8; 8]),
    U128([u8; 16]), // IPv6
    SockaddrV4([u8; 1 + 4 + 2]),
    SockaddrV6([u8; 1 + 16 + 2]),
    SockTupleV4([u8; 1 + 2 * (4 + 2)]),
    Vec(Vec<u8>),
}

impl ToBytes for StaticRepr {
    fn binary_size(&self) -> usize {
        match self {
            StaticRepr::None => 0,
            StaticRepr::U8(v) => v.len(),
            StaticRepr::U16(v) => v.len(),
            StaticRepr::U32(v) => v.len(),
            StaticRepr::U64(v) => v.len(),
            StaticRepr::U128(v) => v.len(),
            StaticRepr::SockaddrV4(v) => v.len(),
            StaticRepr::SockaddrV6(v) => v.len(),
            StaticRepr::SockTupleV4(v) => v.len(),
            StaticRepr::Vec(v) => v.len(),
        }
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            StaticRepr::None => Ok(()),
            StaticRepr::U8(v) => writer.write_all(v.as_slice()),
            StaticRepr::U16(v) => writer.write_all(v.as_slice()),
            StaticRepr::U32(v) => writer.write_all(v.as_slice()),
            StaticRepr::U64(v) => writer.write_all(v.as_slice()),
            StaticRepr::U128(v) => writer.write_all(v.as_slice()),
            StaticRepr::SockaddrV4(v) => writer.write_all(v.as_slice()),
            StaticRepr::SockaddrV6(v) => writer.write_all(v.as_slice()),
            StaticRepr::SockTupleV4(v) => writer.write_all(v.as_slice()),
            StaticRepr::Vec(v) => writer.write_all(v.as_slice()),
        }
    }

    fn default_repr() -> impl ToBytes {
        Self::None
    }
}

macro_rules! impl_static_repr_from_fixed_size {
    ($size:expr => $variant:path) => {
        impl From<[u8; $size]> for StaticRepr {
            fn from(v: [u8; $size]) -> Self {
                $variant(v)
            }
        }
    };
}

impl_static_repr_from_fixed_size!(1 => StaticRepr::U8);
impl_static_repr_from_fixed_size!(2 => StaticRepr::U16);
impl_static_repr_from_fixed_size!(4 => StaticRepr::U32);
impl_static_repr_from_fixed_size!(8 => StaticRepr::U64);
impl_static_repr_from_fixed_size!(16 => StaticRepr::U128);
impl_static_repr_from_fixed_size!(1 + 4 + 2 => StaticRepr::SockaddrV4);
impl_static_repr_from_fixed_size!(1 + 16 + 2 => StaticRepr::SockaddrV6);
impl_static_repr_from_fixed_size!(1 + 2 * (4 + 2) => StaticRepr::SockTupleV4);

#[derive(Debug, Deserialize)]
pub enum Repr {
    Static(StaticRepr),
    Dynamic(u8, StaticRepr),
}

impl ToBytes for Repr {
    fn binary_size(&self) -> usize {
        match self {
            Repr::Static(r) => r.binary_size(),
            Repr::Dynamic(_, r) => 1 + r.binary_size(),
        }
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        match self {
            Repr::Static(r) => r.write(writer),
            Repr::Dynamic(disc, r) => {
                writer.write_all(&[*disc])?;
                r.write(writer)
            }
        }
    }

    fn default_repr() -> impl ToBytes {
        Repr::Static(StaticRepr::None)
    }
}

#[derive(Debug)]
pub struct TaggedRepr<T: ?Sized> {
    pub repr: Repr,
    tag: PhantomData<T>,
}

impl<'de, T> Deserialize<'de> for TaggedRepr<Option<T>>
where
    TaggedRepr<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val: Option<TaggedRepr<T>> = Deserialize::deserialize(deserializer)?;
        let repr = val
            .map(|v| v.repr)
            .unwrap_or(Repr::Static(StaticRepr::None));

        Ok(Self {
            repr,
            tag: PhantomData,
        })
    }
}
