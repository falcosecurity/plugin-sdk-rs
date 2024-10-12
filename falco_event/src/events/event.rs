use crate::event_derive::{EventMetadata, Format, PayloadToBytes};
use crate::events::to_bytes::EventToBytes;
use crate::types::format::format_type;
use std::fmt::{Debug, Formatter};
use std::io::Write;

#[derive(Clone)]
pub struct Event<T> {
    pub metadata: EventMetadata,
    pub params: T,
}

impl<T: Debug + Format<format_type::PF_NA>> Debug for Event<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.debug_struct("Event")
                .field("metadata", &self.metadata)
                .field("params", &self.params)
                .finish()
        } else {
            self.format(f)
        }
    }
}

impl<T: PayloadToBytes> EventToBytes for Event<T> {
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.params.write(&self.metadata, writer)
    }
}

impl<T, F> Format<F> for Event<T>
where
    EventMetadata: Format<F>,
    T: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        self.metadata.format(fmt)?;
        fmt.write_str(" ")?;
        self.params.format(fmt)
    }
}

mod serde_event {
    use super::*;
    use crate::events::types::AnyEvent;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize)]
    struct BorrowedSerializableEvent<'a> {
        #[serde(flatten)]
        pub metadata: &'a EventMetadata,
        #[serde(flatten)]
        pub params: &'a AnyEvent<'a>,
    }

    impl Serialize for Event<AnyEvent<'_>> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let se = BorrowedSerializableEvent {
                metadata: &self.metadata,
                params: &self.params,
            };

            se.serialize(serializer)
        }
    }

    #[derive(Serialize)]
    struct OwnedSerializableEvent<'a> {
        #[serde(flatten)]
        pub metadata: &'a EventMetadata,
        #[serde(flatten)]
        pub params: &'a crate::events::types::owned::AnyEvent,
    }

    impl Serialize for Event<crate::events::types::owned::AnyEvent> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let se = OwnedSerializableEvent {
                metadata: &self.metadata,
                params: &self.params,
            };

            se.serialize(serializer)
        }
    }

    #[derive(Deserialize)]
    struct OwnedDeserializableEvent {
        #[serde(flatten)]
        pub metadata: EventMetadata,
        #[serde(flatten)]
        pub params: crate::events::types::owned::AnyEvent,
    }

    impl<'de> Deserialize<'de> for Event<crate::events::types::owned::AnyEvent> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let de: OwnedDeserializableEvent = Deserialize::deserialize(deserializer)?;

            Ok(Self {
                metadata: de.metadata,
                params: de.params,
            })
        }
    }
}
