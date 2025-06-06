use super::Repr;
use super::StaticRepr;
use super::TaggedRepr;
use serde::Deserialize;
use serde::Deserializer;
use std::marker::PhantomData;

macro_rules! impl_deserialize_int {
    ($ty:ty) => {
        impl<'de> Deserialize<'de> for TaggedRepr<$ty> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let val: $ty = Deserialize::deserialize(deserializer)?;
                Ok(Self {
                    repr: Repr::Static(StaticRepr::from(val.to_ne_bytes())),
                    tag: PhantomData,
                })
            }
        }
    };
}

impl_deserialize_int!(u8);
impl_deserialize_int!(u16);
impl_deserialize_int!(u32);
impl_deserialize_int!(u64);
impl_deserialize_int!(i8);
impl_deserialize_int!(i16);
impl_deserialize_int!(i32);
impl_deserialize_int!(i64);
