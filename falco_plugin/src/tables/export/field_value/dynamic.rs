use crate::tables::export::field_value::traits::seal;
use crate::tables::export::field_value::traits::FieldValue;
use crate::tables::FieldTypeId;
use falco_plugin_api::ss_plugin_state_data;
use std::ffi::{CStr, CString};

/// # A value actually stored in a dynamic table
///
/// This corresponds to `ss_plugin_state_data` in the plugin API.
#[allow(missing_docs)]
#[derive(Debug, Default)]
pub enum DynamicFieldValue {
    #[default]
    None,
    U8(u8),
    I8(i8),
    U16(u16),
    I16(i16),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    Bool(bool),
    String(CString),
}

impl DynamicFieldValue {
    pub(crate) unsafe fn from_data(
        value: &ss_plugin_state_data,
        type_id: FieldTypeId,
    ) -> Option<Self> {
        unsafe {
            match type_id {
                FieldTypeId::I8 => Some(Self::I8(value.s8)),
                FieldTypeId::I16 => Some(Self::I16(value.s16)),
                FieldTypeId::I32 => Some(Self::I32(value.s32)),
                FieldTypeId::I64 => Some(Self::I64(value.s64)),
                FieldTypeId::U8 => Some(Self::U8(value.u8_)),
                FieldTypeId::U16 => Some(Self::U16(value.u16_)),
                FieldTypeId::U32 => Some(Self::U32(value.u32_)),
                FieldTypeId::U64 => Some(Self::U64(value.u64_)),
                FieldTypeId::String => Some(Self::String(CStr::from_ptr(value.str_).to_owned())),
                FieldTypeId::Bool => Some(Self::Bool(value.b != 0)),
                _ => None,
            }
        }
    }
}

impl seal::Sealed for DynamicFieldValue {}

impl FieldValue for DynamicFieldValue {
    fn to_data(
        &self,
        out: &mut ss_plugin_state_data,
        type_id: FieldTypeId,
    ) -> Result<(), anyhow::Error> {
        match self {
            DynamicFieldValue::U8(v) if type_id == FieldTypeId::U8 => out.u8_ = *v,
            DynamicFieldValue::I8(v) if type_id == FieldTypeId::I8 => out.s8 = *v,
            DynamicFieldValue::U16(v) if type_id == FieldTypeId::U16 => out.u16_ = *v,
            DynamicFieldValue::I16(v) if type_id == FieldTypeId::I16 => out.s16 = *v,
            DynamicFieldValue::U32(v) if type_id == FieldTypeId::U32 => out.u32_ = *v,
            DynamicFieldValue::I32(v) if type_id == FieldTypeId::I32 => out.s32 = *v,
            DynamicFieldValue::U64(v) if type_id == FieldTypeId::U64 => out.u64_ = *v,
            DynamicFieldValue::I64(v) if type_id == FieldTypeId::I64 => out.s64 = *v,
            DynamicFieldValue::Bool(v) if type_id == FieldTypeId::Bool => {
                out.b = if *v { 1 } else { 0 }
            }
            DynamicFieldValue::String(v) if type_id == FieldTypeId::String => {
                out.str_ = v.as_c_str().as_ptr()
            }
            _ => anyhow::bail!("Type mismatch, requested {:?}, got {:?}", type_id, self),
        };

        Ok(())
    }
}
