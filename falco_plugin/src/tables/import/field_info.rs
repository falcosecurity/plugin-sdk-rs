use crate::tables::FieldTypeId;
use num_traits::FromPrimitive;
use std::fmt::Debug;

/// Information about a table field
#[repr(transparent)]
pub struct FieldInfo(falco_plugin_api::ss_plugin_table_fieldinfo);

impl Debug for FieldInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInfo")
            .field("name", &self.name())
            .field("read_only", &self.read_only())
            .field("field_type", &self.field_type())
            .finish()
    }
}

impl FieldInfo {
    /// Returns the name of the field
    ///
    /// If the field name cannot be represented as UTF-8, returns "&lt;invalid field name&gt;"
    pub fn name(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.0.name) }
            .to_str()
            .unwrap_or("<invalid field name>")
    }

    /// Returns true if the current field is read-only
    pub fn read_only(&self) -> bool {
        self.0.read_only != 0
    }

    /// Returns the type of the field
    ///
    /// If the type cannot be represented as a [`FieldTypeId`], returns an error
    /// with the raw field type value.
    pub fn field_type(&self) -> Result<FieldTypeId, u32> {
        match FieldTypeId::from_u32(self.0.field_type) {
            Some(field_type) => Ok(field_type),
            None => Err(self.0.field_type),
        }
    }
}
