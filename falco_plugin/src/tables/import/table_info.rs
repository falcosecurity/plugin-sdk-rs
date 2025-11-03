use crate::tables::FieldTypeId;
use num_traits::FromPrimitive;
use std::fmt::Debug;

/// Information about a table
#[repr(transparent)]
pub struct TableInfo(falco_plugin_api::ss_plugin_table_info);

impl Debug for TableInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TableInfo")
            .field("name", &self.name())
            .field("key_type", &self.key_type())
            .finish()
    }
}

impl TableInfo {
    /// Returns the name of the table
    ///
    /// If the table name cannot be represented as UTF-8, returns "&lt;invalid table name&gt;"
    pub fn name(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.0.name) }
            .to_str()
            .unwrap_or("<invalid table name>")
    }

    /// Returns the type of the table's key
    ///
    /// If the type cannot be represented as a [`FieldTypeId`], returns an error
    /// with the raw field type value.
    pub fn key_type(&self) -> Result<FieldTypeId, u32> {
        match FieldTypeId::from_u32(self.0.key_type) {
            Some(field_type) => Ok(field_type),
            None => Err(self.0.key_type),
        }
    }
}
