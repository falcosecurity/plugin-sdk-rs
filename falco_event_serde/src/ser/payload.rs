use crate::ser::field::SerializedField;
use derive_deftly::derive_deftly_adhoc;
use serde::Serialize;
use serde::ser::SerializeStruct;

pub struct SerializedPayload<T>(T);

falco_event::derive_deftly_for_events! {
    impl<$tgens> Serialize for SerializedPayload<&falco_event::events::types::$ttype> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            #[allow(clippy::identity_op)]
            let nfields = 0 ${for fields {+ 1}};

            #[allow(unused_mut)]
            let mut state = serializer.serialize_struct(
                stringify!($tname),
                nfields,
            )?;

            $(state.serialize_field(
                stringify!($fname),
                &SerializedField(&self.0.$fname),
            )?;)

            state.end()
        }
    }
}

derive_deftly_adhoc! {
    falco_event::AnyEvent:

    #[derive(Serialize)]
    pub enum AnyEvent<$tgens 'ser> {
        $(${vdefbody $vname $(${fdefine $fname} SerializedPayload<&'ser falco_event::events::types::$ftype>)})
    }

    impl<'a, 'ser> From<&'ser falco_event::events::types::AnyEvent<'a>> for AnyEvent<'a, 'ser> {
        fn from(event: &'ser falco_event::events::types::AnyEvent<'a>) -> Self {
            match event {
                $(falco_event::events::types::AnyEvent::$vname(f_0) => AnyEvent::$vname(SerializedPayload(f_0)),)
            }
        }
    }

    ${for fields {
        impl<'a, 'ser> From<&'ser falco_event::events::types::$ftype> for AnyEvent<'a, 'ser> {
            fn from(event: &'ser falco_event::events::types::$ftype) -> Self {
                AnyEvent::$vname(SerializedPayload(event))
            }
        }
    }}
}
