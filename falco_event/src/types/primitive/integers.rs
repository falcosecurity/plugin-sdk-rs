use crate::fields::{FromBytes, FromBytesError, ToBytes};
use byteorder::{ReadBytesExt, WriteBytesExt};

macro_rules! impl_int_type {
    ($ty:ty) => {
        impl FromBytes<'_> for $ty {
            fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError>
            where
                Self: Sized,
            {
                Ok(buf.read_int::<byteorder::NativeEndian>(std::mem::size_of::<$ty>())? as $ty)
            }
        }

        impl ToBytes for $ty {
            fn binary_size(&self) -> usize {
                std::mem::size_of::<$ty>()
            }

            fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
                writer
                    .write_int::<byteorder::NativeEndian>(*self as i64, std::mem::size_of::<$ty>())
            }

            fn default_repr() -> impl ToBytes {
                0 as $ty
            }
        }
    };
}

macro_rules! impl_uint_type {
    ($ty:ty) => {
        impl FromBytes<'_> for $ty {
            fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError>
            where
                Self: Sized,
            {
                Ok(buf.read_uint::<byteorder::NativeEndian>(std::mem::size_of::<$ty>())? as $ty)
            }
        }

        impl ToBytes for $ty {
            fn binary_size(&self) -> usize {
                std::mem::size_of::<$ty>()
            }

            fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
                writer
                    .write_uint::<byteorder::NativeEndian>(*self as u64, std::mem::size_of::<$ty>())
            }

            fn default_repr() -> impl ToBytes {
                0 as $ty
            }
        }
    };
}

impl_int_type!(u8);
impl_uint_type!(i8);
impl_int_type!(u16);
impl_uint_type!(i16);
impl_int_type!(u32);
impl_uint_type!(i32);
impl_int_type!(u64);
impl_uint_type!(i64);
