use crate::ser::field::SerializedField;
use serde::Serialize;

falco_event::derive_deftly_for_dynamic_params!(
    impl<$tgens> Serialize for SerializedField<&falco_event::fields::types::$tname<$tgens>> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            #[derive(Serialize)]
            enum Param<$tgens 'ser> {
                $(
                    ${vdefbody $vname $(SerializedField<&'ser $ftype>)}
                )
            }

            let val = match self.0 {
                $(falco_event::fields::types::$tname::$vname(f_0) => Param::$vname(SerializedField(f_0)),)
            };
            val.serialize(serializer)
        }
    }
);
