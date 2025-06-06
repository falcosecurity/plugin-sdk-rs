use super::Repr;
use super::StaticRepr;
use super::TaggedRepr;
use falco_event::fields::types;
use serde::Deserialize;
use serde::Deserializer;
use std::marker::PhantomData;

macro_rules! impl_deserialize_newtype {
    ($ty:path) => {
        impl<'de> Deserialize<'de> for TaggedRepr<$ty> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let val = $ty(Deserialize::deserialize(deserializer)?);
                Ok(Self {
                    repr: Repr::Static(StaticRepr::from(val.0.to_ne_bytes())),
                    tag: PhantomData,
                })
            }
        }
    };
}

impl_deserialize_newtype!(types::PT_BOOL);
impl_deserialize_newtype!(types::PT_FD);
impl_deserialize_newtype!(types::PT_GID);
impl_deserialize_newtype!(types::PT_PID);
impl_deserialize_newtype!(types::PT_PORT);
impl_deserialize_newtype!(types::PT_SIGSET);
impl_deserialize_newtype!(types::PT_SIGTYPE);
impl_deserialize_newtype!(types::PT_SOCKFAMILY);
impl_deserialize_newtype!(types::PT_SYSCALLID);
impl_deserialize_newtype!(types::PT_ERRNO);
impl_deserialize_newtype!(types::PT_UID);
