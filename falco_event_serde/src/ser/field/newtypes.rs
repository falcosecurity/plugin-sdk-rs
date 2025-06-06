use crate::ser::field::SerializedField;
use falco_event::fields::types;
use serde::Serialize;
use serde::Serializer;

macro_rules! impl_serialize_newtype {
    ($ty:ty) => {
        impl Serialize for SerializedField<&$ty> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.0.serialize(serializer)
            }
        }
    };
}

impl_serialize_newtype!(types::PT_BOOL);
impl_serialize_newtype!(types::PT_FD);
impl_serialize_newtype!(types::PT_GID);
impl_serialize_newtype!(types::PT_PID);
impl_serialize_newtype!(types::PT_PORT);
impl_serialize_newtype!(types::PT_SIGSET);
impl_serialize_newtype!(types::PT_SIGTYPE);
impl_serialize_newtype!(types::PT_SOCKFAMILY);
impl_serialize_newtype!(types::PT_SYSCALLID);
impl_serialize_newtype!(types::PT_ERRNO);
impl_serialize_newtype!(types::PT_UID);
