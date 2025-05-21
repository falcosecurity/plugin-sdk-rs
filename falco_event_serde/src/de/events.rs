use crate::de::repr::Repr;
use falco_event::events::EventMetadata;
use falco_event::fields::ToBytes;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RawEvent {
    pub ts: u64,
    pub tid: i64,
    pub event_type_id: u16,
    pub large_payload: bool,
    pub params: Vec<Repr>,
}

impl RawEvent {
    pub fn append_to_vec(&self, mut buf: &mut Vec<u8>) {
        let meta = EventMetadata {
            ts: self.ts,
            tid: self.tid,
        };

        let lengths = self
            .params
            .iter()
            .map(|p| p.binary_size())
            .collect::<Vec<usize>>();

        let len_size = match self.large_payload {
            true => 4,
            false => 2,
        };

        let len = 26 + (len_size * lengths.len()) + lengths.iter().sum::<usize>();
        meta.write_header(
            len as u32,
            self.event_type_id,
            lengths.len() as u32,
            &mut buf,
        )
        .unwrap();

        if self.large_payload {
            for len in lengths {
                buf.extend_from_slice(&(len as u32).to_ne_bytes());
            }
        } else {
            for len in lengths {
                buf.extend_from_slice(&(len as u16).to_ne_bytes());
            }
        }

        for param in &self.params {
            param.write(&mut buf).unwrap();
        }
    }
}

pub trait ToRawEvent {
    fn to_raw(self, metadata: &EventMetadata) -> RawEvent;
}

/// Represents a deserialized Falco event.
///
/// This struct contains an intermediate representation of a Falco event that can be serialized
/// into a byte vector using [`Event::to_vec`] or appended to an existing byte vector using
/// [`Event::append_to_vec`]. The resulting byte vector can then be parsed into
/// a [`falco_event::events::RawEvent`] and further into a concrete event type.
#[derive(Debug, Deserialize)]
pub struct Event {
    ts: u64,
    tid: i64,
    #[serde(flatten)]
    event: crate::de::payload::AnyEvent<'static>,
}

impl Event {
    /// Appends the serialized event to the provided byte vector.
    pub fn append_to_vec(self, buf: &mut Vec<u8>) {
        let metadata = EventMetadata {
            ts: self.ts,
            tid: self.tid,
        };
        self.event.to_raw(&metadata).append_to_vec(buf)
    }

    /// Converts the event into a byte vector.
    pub fn to_vec(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.append_to_vec(&mut buf);
        buf
    }
}
