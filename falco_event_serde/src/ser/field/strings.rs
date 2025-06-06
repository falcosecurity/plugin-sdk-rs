use crate::ser::field::SerializedField;
use falco_event::fields::types;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

pub struct StrOrBytes<'a>(pub &'a [u8]);

impl<'a> Serialize for StrOrBytes<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let val = self.0;
        if serializer.is_human_readable() {
            match std::str::from_utf8(val) {
                Ok(s) => s.serialize(serializer),
                Err(_) => {
                    // If it's not valid UTF-8, serialize as a byte array
                    val.serialize(serializer)
                }
            }
        } else {
            // If not human-readable, serialize as a byte array
            val.serialize(serializer)
        }
    }
}

impl Serialize for SerializedField<&&types::PT_FSPATH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        StrOrBytes(self.0.as_bytes()).serialize(serializer)
    }
}

impl Serialize for SerializedField<&types::PT_FSRELPATH<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        StrOrBytes(self.0.0.as_bytes()).serialize(serializer)
    }
}

impl Serialize for SerializedField<&&types::PT_BYTEBUF> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        StrOrBytes(self.0).serialize(serializer)
    }
}

impl Serialize for SerializedField<&&types::PT_CHARBUF> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        StrOrBytes(self.0.to_bytes()).serialize(serializer)
    }
}

impl Serialize for SerializedField<&types::PT_CHARBUFARRAY<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_seq(Some(self.0.len()))?;
        for item in self.0 {
            state.serialize_element(&StrOrBytes(item.to_bytes()))?;
        }
        state.end()
    }
}

impl Serialize for SerializedField<&types::PT_CHARBUF_PAIR_ARRAY<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_seq(Some(self.0.len()))?;
        for (k, v) in self.0 {
            state.serialize_element(&(StrOrBytes(k.to_bytes()), StrOrBytes(v.to_bytes())))?;
        }
        state.end()
    }
}
