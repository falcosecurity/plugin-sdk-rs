use std::io::Write;

use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};

use crate::events::payload::{
    EventPayload, PayloadFromBytes, PayloadFromBytesError, PayloadFromBytesResult,
};
use crate::events::{Event, EventMetadata, EventToBytes};
use crate::fields::FromBytesError;

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

    pub fn load<'a, T: PayloadFromBytes<'a> + EventPayload>(
        &'a self,
    ) -> PayloadFromBytesResult<Event<T>> {
        if self.event_type != T::ID as u16 {
            return Err(PayloadFromBytesError::TypeMismatch);
        }
        let params = unsafe {
            if T::LARGE {
                T::read(self.params::<u32>()?)
            } else {
                T::read(self.params::<u16>()?)
            }
        }?;
        Ok(Event {
            metadata: self.metadata.clone(),
            params,
        })
    }

    unsafe fn lengths_length<T>(&self) -> usize {
        let size = std::mem::size_of::<T>();
        self.nparams as usize * size
    }

    unsafe fn lengths<T>(mut buf: &[u8]) -> impl Iterator<Item = usize> + '_ + use<'_, T> {
        let size = std::mem::size_of::<T>();

        std::iter::from_fn(move || buf.read_uint::<NativeEndian>(size).ok().map(|s| s as usize))
    }

    /// # Safety
    ///
    /// `T` must correspond to the type of the length field (u16 or u32, depending on event type)
    pub unsafe fn params<T>(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<&'e [u8], FromBytesError>> + use<'e, T>,
        PayloadFromBytesError,
    > {
        let ll = unsafe { self.lengths_length::<T>() };

        if self.payload.len() < ll {
            return Err(PayloadFromBytesError::TruncatedEvent {
                wanted: ll,
                got: self.payload.len(),
            });
        }

        let (lengths, mut params) = self.payload.split_at(ll);
        let mut lengths = unsafe { Self::lengths::<T>(lengths) };

        Ok(std::iter::from_fn(move || {
            let len = lengths.next()?;
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
        writer.write_u64::<NativeEndian>(self.metadata.ts)?;
        writer.write_i64::<NativeEndian>(self.metadata.tid)?;

        writer.write_u32::<NativeEndian>(self.len)?;
        writer.write_u16::<NativeEndian>(self.event_type)?;
        writer.write_u32::<NativeEndian>(self.nparams)?;

        writer.write_all(self.payload)
    }
}
