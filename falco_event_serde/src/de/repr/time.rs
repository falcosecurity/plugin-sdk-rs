use super::{StaticRepr, TaggedRepr};
use crate::de::repr::Repr::Static;
use falco_event::fields::types;
use serde::Deserialize;
use serde::Deserializer;
use serde::de::Error;
use std::marker::PhantomData;
use std::time::{Duration, SystemTime};

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_RELTIME> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let reltime: Duration = Deserialize::deserialize(deserializer)?;
        Ok(Self {
            repr: Static(StaticRepr::U64((reltime.as_nanos() as u64).to_ne_bytes())),
            tag: PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for TaggedRepr<types::PT_ABSTIME> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let abstime: SystemTime = Deserialize::deserialize(deserializer)?;
        let reltime = abstime
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(Error::custom)?;
        Ok(Self {
            repr: Static(StaticRepr::U64((reltime.as_nanos() as u64).to_ne_bytes())),
            tag: PhantomData,
        })
    }
}
