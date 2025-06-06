use crate::de::repr::{Repr, TaggedRepr};
use serde::{Deserialize, Deserializer};
use std::marker::PhantomData;

falco_event::derive_deftly_for_dynamic_params! {
    ${define INFERRED_GENS {
        ${if tgens { '_ }}
    }}

    ${define STATIC_GENS {
        ${if tgens { 'static }}
    }}

    impl<'de> Deserialize<'de> for TaggedRepr<falco_event::fields::types::$tname<$INFERRED_GENS>> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {

            #[derive(Deserialize)]
            enum Param<$tgens> {
                $(
                    ${vdefbody $vname $(TaggedRepr<$ftype>)}
                )
            }

            let val: Param<$STATIC_GENS> = Deserialize::deserialize(deserializer)?;

            let repr = match val {
                $(Param::$vname(f_0) => {
                    if let Repr::Static(repr) = f_0.repr {
                        Repr::Dynamic(falco_event::ffi::$vname as u8, repr)
                    } else {
                        unimplemented!()
                    }
                })
            };

            Ok(Self {
                repr,
                tag: PhantomData,
            })
        }
    }
}
