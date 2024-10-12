use crate::fields::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::{format_type, Format};
use crate::types::{BorrowDeref, Borrowed};
use byteorder::{ReadBytesExt, WriteBytesExt};

macro_rules! impl_format {
    ($ty:ty) => {
        impl Format<format_type::PF_NA> for $ty {
            fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                std::fmt::Display::fmt(self, fmt)
            }
        }

        impl Format<format_type::PF_DEC> for $ty {
            fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                std::fmt::Display::fmt(self, fmt)
            }
        }

        impl Format<format_type::PF_HEX> for $ty {
            fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(fmt, "{:#x}", self)
            }
        }

        impl Format<format_type::PF_OCT> for $ty {
            fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(fmt, "{:#o}", self)
            }
        }
    };
}

macro_rules! impl_borrow_deref {
    ($ty:ty) => {
        impl Borrowed for $ty {
            type Owned = Self;
        }

        impl BorrowDeref for $ty {
            type Target<'a> = Self;

            fn borrow_deref(&self) -> Self::Target<'_> {
                *self
            }
        }
    };
}

macro_rules! impl_int_type {
    ($ty:ty) => {
        impl FromBytes<'_> for $ty {
            fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self>
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

        impl_format!($ty);
        impl_borrow_deref!($ty);
    };
}

macro_rules! impl_uint_type {
    ($ty:ty) => {
        impl FromBytes<'_> for $ty {
            fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self>
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

        impl_format!($ty);
        impl_borrow_deref!($ty);
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
