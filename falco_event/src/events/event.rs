use crate::events::to_bytes::EventToBytes;
use crate::events::{EventMetadata, PayloadToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;

#[derive(Clone)]
pub struct Event<T> {
    pub metadata: EventMetadata,
    pub params: T,
}

impl<T: Debug> Debug for Event<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {:?}", self.metadata, self.params)
    }
}

impl<T: PayloadToBytes> EventToBytes for Event<T> {
    fn binary_size(&self) -> usize {
        26 + self.params.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.params.write(&self.metadata, writer)
    }
}
