use crate::ser::field::SerializedField;
use falco_event::fields::types;
use serde::{Serialize, Serializer};

impl Serialize for SerializedField<&types::PT_ABSTIME> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let nanos = self
            .0
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .map_err(serde::ser::Error::custom)? as u64;
        nanos.serialize(serializer)
    }
}

impl Serialize for SerializedField<&types::PT_RELTIME> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let nanos = self.0.as_nanos() as u64;
        nanos.serialize(serializer)
    }
}
