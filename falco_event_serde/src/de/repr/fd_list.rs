use crate::de::repr::Repr::Static;
use crate::de::repr::{StaticRepr, TaggedRepr};
use falco_event::fields::types;
use serde::{Deserialize, Deserializer};
use std::marker::PhantomData;

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_FDLIST> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fdlist: Vec<(u64, u16)> = Deserialize::deserialize(deserializer)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice((fdlist.len() as u16).to_ne_bytes().as_slice());
        for (fd, flags) in fdlist {
            bytes.extend_from_slice(fd.to_ne_bytes().as_slice());
            bytes.extend_from_slice(flags.to_ne_bytes().as_slice());
        }

        Ok(Self {
            repr: Static(StaticRepr::Vec(bytes)),
            tag: PhantomData,
        })
    }
}
