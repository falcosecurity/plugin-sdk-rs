use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::exported_tables::field_value::traits::{seal, FieldValue, StaticField};
use crate::tables::import::data::FieldTypeId;
use falco_plugin_api::ss_plugin_state_data;
use std::ffi::CString;

macro_rules! impl_primitive_field_value {
    (bool, $self:ident) => {
        if *$self {
            1
        } else {
            0
        }
    };
    (CString, $self:ident) => {
        $self.as_ptr()
    };
    ($_:ty, $self:ident) => {
        *$self
    };
}

macro_rules! impl_scalar_field {
    ($ty:tt => $datafield:ident => $type_id:expr => $variant:ident) => {
        impl seal::Sealed for $ty {}

        impl FieldValue for $ty {
            fn to_data(
                &self,
                out: &mut ss_plugin_state_data,
                type_id: FieldTypeId,
            ) -> Result<(), anyhow::Error> {
                if type_id != $type_id {
                    anyhow::bail!(
                        "Type mismatch, requested {:?}, got {:?}",
                        type_id,
                        stringify!($ty)
                    )
                }

                out.$datafield = impl_primitive_field_value!($ty, self);
                Ok(())
            }
        }

        impl StaticField for $ty {
            const TYPE_ID: FieldTypeId = $type_id;
            const READONLY: bool = false;
        }

        impl TryFrom<DynamicFieldValue> for $ty {
            type Error = anyhow::Error;

            fn try_from(value: DynamicFieldValue) -> Result<Self, Self::Error> {
                if let DynamicFieldValue::$variant(val) = value {
                    Ok(val)
                } else {
                    Err(anyhow::anyhow!(
                        "Type mismatch, expected {}, got {:?}",
                        stringify!($ty),
                        value
                    ))
                }
            }
        }
    };
}

impl_scalar_field!(u8 => u8_ => FieldTypeId::U8 => U8);
impl_scalar_field!(i8 => s8 => FieldTypeId::I8 => I8);
impl_scalar_field!(u16 => u16_ => FieldTypeId::U16 => U16);
impl_scalar_field!(i16 => s16 => FieldTypeId::I16 => I16);
impl_scalar_field!(u32 => u32_ => FieldTypeId::U32 => U32);
impl_scalar_field!(i32 => s32 => FieldTypeId::I32 => I32);
impl_scalar_field!(u64 => u64_ => FieldTypeId::U64 => U64);
impl_scalar_field!(i64 => s64 => FieldTypeId::I64 => I64);
impl_scalar_field!(bool => b => FieldTypeId::Bool => Bool);
impl_scalar_field!(CString => str_ => FieldTypeId::String => String);
