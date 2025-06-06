use crate::ser::field::{SerializedField, StrOrBytes};
use falco_event::fields::types;
use serde::{Serialize, Serializer};

impl Serialize for SerializedField<&types::PT_SOCKADDR<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            types::PT_SOCKADDR::Unix(path) => SerializedField(path).serialize(serializer),
            types::PT_SOCKADDR::V4((addr, port)) => {
                (addr, SerializedField(port)).serialize(serializer)
            }
            types::PT_SOCKADDR::V6((addr, port)) => {
                (addr, SerializedField(port)).serialize(serializer)
            }
            types::PT_SOCKADDR::Other(af, addr) => (af, StrOrBytes(addr)).serialize(serializer),
        }
    }
}

impl Serialize for SerializedField<&types::PT_SOCKTUPLE<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            types::PT_SOCKTUPLE::Unix {
                source_ptr,
                dest_ptr,
                path,
            } => (source_ptr, dest_ptr, SerializedField(path)).serialize(serializer),
            types::PT_SOCKTUPLE::V4 { source, dest } => (
                source.0,
                SerializedField(&source.1),
                dest.0,
                SerializedField(&dest.1),
            )
                .serialize(serializer),
            types::PT_SOCKTUPLE::V6 { source, dest } => (
                source.0,
                SerializedField(&source.1),
                dest.0,
                SerializedField(&dest.1),
            )
                .serialize(serializer),
            types::PT_SOCKTUPLE::Other(af, addr) => (af, StrOrBytes(addr)).serialize(serializer),
        }
    }
}
