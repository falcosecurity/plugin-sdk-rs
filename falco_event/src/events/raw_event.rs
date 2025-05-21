use std::io::Write;

use byteorder::{NativeEndian, ReadBytesExt};

use crate::events::payload::PayloadFromBytesError;
use crate::events::{Event, EventMetadata, EventToBytes};
use crate::fields::FromBytesError;

pub trait FromRawEvent<'a>: Sized {
    fn parse(raw_event: &RawEvent<'a>) -> Result<Self, PayloadFromBytesError>;
}

#[derive(Debug)]
pub struct RawEvent<'a> {
    pub metadata: EventMetadata,
    pub len: u32,
    pub event_type: u16,
    pub nparams: u32,
    pub payload: &'a [u8],
}

impl<'e> RawEvent<'e> {
    pub fn from(mut buf: &[u8]) -> std::io::Result<RawEvent> {
        let ts = buf.read_u64::<NativeEndian>()?;
        let tid = buf.read_i64::<NativeEndian>()?;

        let len = buf.read_u32::<NativeEndian>()?;
        let event_type = buf.read_u16::<NativeEndian>()?;
        let nparams = buf.read_u32::<NativeEndian>()?;

        Ok(RawEvent {
            metadata: EventMetadata { ts, tid },
            len,
            event_type,
            nparams,
            payload: buf,
        })
    }

    /// Trim event payload
    ///
    /// This limits the payload to the length actually indicated in the `len` field
    /// and returns the excess data. Useful when reading a raw event stream without
    /// any external structure
    ///
    /// Example
    /// ```
    /// use falco_event::events::{PayloadFromBytesError, RawEvent};
    /// # fn main() -> anyhow::Result<()> {
    /// let mut events: &[u8] = &[ /* raw event bytes */ ];
    ///
    /// while !events.is_empty() {
    ///     let mut event = RawEvent::from(events)?;
    ///     match event.trim() {
    ///         Some(tail) => events = tail,
    ///         None => return Err(PayloadFromBytesError::TruncatedEvent {
    ///             wanted: event.len as usize,
    ///             got: events.len(),
    ///         })?
    ///     }
    /// }
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn trim(&mut self) -> Option<&'e [u8]> {
        let payload_len = self.len as usize - 26;
        self.payload.split_off(payload_len..)
    }

    /// Iterate over a buffer with multiple raw events
    ///
    /// This function takes a byte slice and returns an iterator that yields `RawEvent` instances
    /// until the whole buffer is consumed.
    pub fn scan(mut buf: &'e [u8]) -> impl Iterator<Item = Result<RawEvent<'e>, std::io::Error>> {
        std::iter::from_fn(move || {
            if buf.is_empty() {
                return None;
            }
            match Self::from(buf) {
                Ok(mut raw_event) => {
                    if let Some(tail) = raw_event.trim() {
                        buf = tail;
                    }
                    Some(Ok(raw_event))
                }

                Err(err) => Some(Err(err)),
            }
        })
    }

    /// Parse a byte buffer (from a raw pointer) into a RawEvent
    ///
    /// # Safety
    ///
    /// `buf` must point to a complete event, i.e.
    ///  - include the length field
    ///  - include `nparams` lengths
    ///  - have enough data bytes for all the fields (sum of lengths)
    pub unsafe fn from_ptr<'a>(buf: *const u8) -> std::io::Result<RawEvent<'a>> {
        let mut len_ptr = unsafe { std::slice::from_raw_parts(buf.offset(16), 4) };
        let len = len_ptr.read_u32::<NativeEndian>()?;

        let buf: &'a [u8] = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        Self::from(buf)
    }

    pub fn load<'a, T: FromRawEvent<'e>>(&'a self) -> Result<Event<T>, PayloadFromBytesError> {
        let params = T::parse(self)?;
        Ok(Event {
            metadata: self.metadata.clone(),
            params,
        })
    }

    /// Get an iterator over the event parameters
    ///
    /// `T` must correspond to the type of the length field (u16 or u32, depending on the event type)
    pub fn params<T>(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<&'e [u8], FromBytesError>> + use<'e, T>,
        PayloadFromBytesError,
    > {
        let length_size = size_of::<T>();
        let ll = self.nparams as usize * length_size;

        if self.payload.len() < ll {
            return Err(PayloadFromBytesError::TruncatedEvent {
                wanted: ll,
                got: self.payload.len(),
            });
        }

        let (mut lengths, mut params) = self.payload.split_at(ll);

        Ok(std::iter::from_fn(move || {
            let len = lengths.read_uint::<NativeEndian>(length_size).ok()? as usize;
            if len > params.len() {
                // truncated event, do not return the param fragment, if any
                return Some(Err(FromBytesError::TruncatedField {
                    wanted: len,
                    got: params.len(),
                }));
            }
            let (param, tail) = params.split_at(len);
            params = tail;
            Some(Ok(param))
        }))
    }
}

impl EventToBytes for RawEvent<'_> {
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.metadata
            .write_header(self.len, self.event_type, self.nparams, &mut writer)?;
        writer.write_all(self.payload)
    }
}
