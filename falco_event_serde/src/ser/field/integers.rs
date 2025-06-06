use crate::ser::field::SerializedField;
use serde::{Serialize, Serializer};

macro_rules! impl_serialize_primitive {
    ($ty:ty) => {
        impl Serialize for SerializedField<&$ty> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }
    };
}

impl_serialize_primitive!(u8);
impl_serialize_primitive!(u16);
impl_serialize_primitive!(u32);
impl_serialize_primitive!(u64);
impl_serialize_primitive!(i8);
impl_serialize_primitive!(i16);
impl_serialize_primitive!(i32);
impl_serialize_primitive!(i64);
