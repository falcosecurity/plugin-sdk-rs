use crate::ser::field::SerializedField;
use serde::{Serialize, Serializer};

impl<'a, T> Serialize for SerializedField<&'a Option<T>>
where
    SerializedField<&'a T>: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let val = self.0.as_ref().map(SerializedField);
        val.serialize(serializer)
    }
}
