use crate::ser::field::SerializedField;
use falco_event::fields::types;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

impl Serialize for SerializedField<&types::PT_FDLIST> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_seq(Some(self.0.0.len()))?;
        for (fd, flags) in &self.0.0 {
            state.serialize_element(&(fd, SerializedField(flags)))?;
        }
        state.end()
    }
}
