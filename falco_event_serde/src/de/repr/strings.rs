use super::{StaticRepr, TaggedRepr};
use crate::de::repr::Repr::Static;
use bstr::BString;
use falco_event::fields::types;
use serde::Deserialize;
use serde::Deserializer;
use std::marker::PhantomData;

macro_rules! impl_deserialize_bstr {
    ($tag:ty) => {
        impl<'de> Deserialize<'de> for TaggedRepr<$tag> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let path: BString = Deserialize::deserialize(deserializer)?;
                let mut buf: Vec<u8> = path.into();
                buf.push(b'\0');
                Ok(Self {
                    repr: Static(StaticRepr::Vec(buf)),
                    tag: PhantomData,
                })
            }
        }
    };
}

impl_deserialize_bstr!(&'_ types::PT_CHARBUF);
impl_deserialize_bstr!(&'_ types::PT_FSPATH);
impl_deserialize_bstr!(types::PT_FSRELPATH<'_>);

impl<'de> Deserialize<'de> for TaggedRepr<&types::PT_BYTEBUF> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: BString = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            repr: Static(StaticRepr::Vec(Vec::from(buf.as_slice()))),
            tag: PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_CHARBUFARRAY<'_>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let arr: Vec<BString> = Deserialize::deserialize(deserializer)?;
        let mut buf = Vec::new();
        for item in arr {
            buf.extend_from_slice(item.as_slice());
            buf.push(b'\0');
        }

        Ok(Self {
            repr: Static(StaticRepr::Vec(buf)),
            tag: PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_CHARBUF_PAIR_ARRAY<'_>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let arr: Vec<(BString, BString)> = Deserialize::deserialize(deserializer)?;
        let mut buf = Vec::new();
        for (k, v) in arr {
            buf.extend_from_slice(k.as_slice());
            buf.push(b'\0');
            buf.extend_from_slice(v.as_slice());
            buf.push(b'\0');
        }

        Ok(Self {
            repr: Static(StaticRepr::Vec(buf)),
            tag: PhantomData,
        })
    }
}
