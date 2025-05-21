use crate::de::events::{RawEvent, ToRawEvent};
use crate::de::repr::TaggedRepr;
use derive_deftly::derive_deftly_adhoc;
use falco_event::events::{EventMetadata, EventPayload};
use serde::Deserialize;

falco_event::derive_deftly_for_events! {
    #[derive(Deserialize)]
    #[derive(Debug)]
    struct $tname <$tgens> {
        $($fname: TaggedRepr<$ftype>,)
    }

    impl<$tgens> ToRawEvent for $tname<$tgens> {
        fn to_raw(self, metadata: &EventMetadata) -> RawEvent {
            let params = vec![
                $(self.$fname.repr,)
            ];

            let event_type_id = <falco_event::events::types::$ttype as EventPayload>::ID as u16;
            let large_payload = match size_of::<<falco_event::events::types::$ttype as EventPayload>::LengthType>() {
                2 => false,
                4 => true,
                _ => panic!("Invalid length type for event payload"),
            };

            RawEvent {
                ts: metadata.ts,
                tid: metadata.tid,
                event_type_id,
                large_payload,
                params
            }
        }
    }
}

derive_deftly_adhoc! {
    falco_event::AnyEvent:

    #[derive(Deserialize)]
    #[derive(Debug)]
    pub enum AnyEvent<$tgens> {
        $(${vdefbody $vname $(${fdefine $fname} $ftype)})
    }

    impl<$tgens> ToRawEvent for AnyEvent<$tgens> {
        fn to_raw(self, metadata: &EventMetadata) -> RawEvent {
            match self {
                $(AnyEvent::$vname(event) => event.to_raw(metadata),)
            }
        }
    }
}
