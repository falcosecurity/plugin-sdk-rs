use crate::de::repr::Repr::Static;
use crate::de::repr::StaticRepr;
use crate::de::repr::TaggedRepr;
use serde::{Deserialize, Deserializer};
use std::marker::PhantomData;

falco_event::derive_deftly_for_enums! {
    impl<'de> Deserialize<'de> for TaggedRepr<falco_event::fields::types::$ttype> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let val = falco_event::fields::types::$ttype::new(Deserialize::deserialize(deserializer)?);
            Ok(Self {
                repr: Static(StaticRepr::from(val.as_repr().to_ne_bytes())),
                tag: PhantomData,
            })
        }
    }
}

falco_event::derive_deftly_for_bitflags! {
    impl<'de> Deserialize<'de> for TaggedRepr<falco_event::fields::types::$ttype> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let val = falco_event::fields::types::$ttype::from_bits_retain(Deserialize::deserialize(deserializer)?);
            Ok(Self {
                repr: Static(StaticRepr::from(val.bits().to_ne_bytes())),
                tag: PhantomData,
            })
        }
    }
}
