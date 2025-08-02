use crate::events::payload::PayloadFromBytesError;
use crate::events::{Event, EventMetadata, EventToBytes};
use crate::fields::FromBytesError;
use std::io::Write;
use std::marker::PhantomData;
use std::num::TryFromIntError;

pub trait FromRawEvent<'a>: Sized {
    fn parse(raw_event: &RawEvent<'a>) -> Result<Self, PayloadFromBytesError>;
}

pub trait LengthField: TryFrom<usize, Error = TryFromIntError> {
    fn read(buf: &mut &[u8]) -> Option<usize>;

    fn to_usize(&self) -> usize;
}

impl LengthField for u16 {
    fn read(buf: &mut &[u8]) -> Option<usize> {
        let len = buf.split_off(..size_of::<u16>())?;
        Some(u16::from_ne_bytes(len.try_into().unwrap()) as usize)
    }

    fn to_usize(&self) -> usize {
        *self as usize
    }
}

impl LengthField for u32 {
    fn read(buf: &mut &[u8]) -> Option<usize> {
        let len = buf.split_off(..size_of::<u32>())?;
        Some(u32::from_ne_bytes(len.try_into().unwrap()) as usize)
    }

    fn to_usize(&self) -> usize {
        *self as usize
    }
}

pub struct ParamIter<'a, T: LengthField> {
    lengths: &'a [u8],
    params: &'a [u8],
    length_type: PhantomData<T>,
}

impl<'a, T: LengthField> Iterator for ParamIter<'a, T> {
    type Item = Result<&'a [u8], FromBytesError>;

    fn next(&mut self) -> Option<Self::Item> {
        let len = T::read(&mut self.lengths)?;
        match self.params.split_off(..len) {
            Some(param) => Some(Ok(param)),
            None => Some(Err(FromBytesError::TruncatedField {
                wanted: len,
                got: self.params.len(),
            })),
        }
    }
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
    fn from_impl(mut buf: &[u8]) -> Option<RawEvent<'_>> {
        let ts_buf = buf.split_off(..8)?;
        let ts = u64::from_ne_bytes(ts_buf.try_into().unwrap());

        let tid_buf = buf.split_off(..8)?;
        let tid = i64::from_ne_bytes(tid_buf.try_into().unwrap());

        let len_buf = buf.split_off(..4)?;
        let len = u32::from_ne_bytes(len_buf.try_into().unwrap());

        let event_type_buf = buf.split_off(..2)?;
        let event_type = u16::from_ne_bytes(event_type_buf.try_into().unwrap());

        let nparams_buf = buf.split_off(..4)?;
        let nparams = u32::from_ne_bytes(nparams_buf.try_into().unwrap());

        Some(RawEvent {
            metadata: EventMetadata { ts, tid },
            len,
            event_type,
            nparams,
            payload: buf,
        })
    }

    /// Parse a byte slice into a RawEvent
    ///
    /// This decodes the header while leaving the payload as a raw byte buffer.
    pub fn from(buf: &[u8]) -> std::io::Result<RawEvent<'_>> {
        Self::from_impl(buf).ok_or(std::io::ErrorKind::InvalidData.into())
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
        let len_buf = unsafe { std::slice::from_raw_parts(buf.offset(16), 4) };
        let len = u32::from_ne_bytes(len_buf.try_into().unwrap());

        let buf: &'a [u8] = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        Self::from(buf)
    }

    pub fn load<'a, T: FromRawEvent<'e>>(&'a self) -> Result<Event<T>, PayloadFromBytesError> {
        #[allow(clippy::question_mark)]
        let params = match T::parse(self) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        Ok(Event {
            metadata: self.metadata.clone(),
            params,
        })
    }

    /// Get an iterator over the event parameters
    ///
    /// `T` must correspond to the type of the length field (u16 or u32, depending on the event type)
    pub fn params<T: LengthField>(&self) -> Result<ParamIter<'e, T>, PayloadFromBytesError> {
        let length_size = size_of::<T>();
        let ll = self.nparams as usize * length_size;

        if self.payload.len() < ll {
            return Err(PayloadFromBytesError::TruncatedEvent {
                wanted: ll,
                got: self.payload.len(),
            });
        }

        let (lengths, params) = self.payload.split_at(ll);

        Ok(ParamIter {
            lengths,
            params,
            length_type: PhantomData,
        })
    }
}

impl EventToBytes for RawEvent<'_> {
    fn binary_size(&self) -> usize {
        self.len as usize
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.metadata
            .write_header(self.len, self.event_type, self.nparams, &mut writer)?;
        writer.write_all(self.payload)
    }
}
