use crate::plugin::tables::vtable::TableError;
use crate::plugin::tables::vtable::TableError::BadVtable;
use falco_plugin_api::{
    ss_plugin_state_type, ss_plugin_table_field_t, ss_plugin_table_fieldinfo,
    ss_plugin_table_fields_vtable_ext, ss_plugin_table_t,
};

#[derive(Debug)]
pub struct TableFields<'t> {
    fields_ext: &'t ss_plugin_table_fields_vtable_ext,
}

impl<'t> TableFields<'t> {
    pub(super) fn try_from(
        fields_ext: &'t ss_plugin_table_fields_vtable_ext,
    ) -> Result<Self, TableError> {
        Ok(TableFields { fields_ext })
    }

    pub(in crate::plugin::tables) fn list_table_fields(
        &self,
        t: *mut ss_plugin_table_t,
        nfields: *mut u32,
    ) -> Result<*const ss_plugin_table_fieldinfo, TableError> {
        unsafe {
            Ok(self
                .fields_ext
                .list_table_fields
                .ok_or(BadVtable("list_table_fields"))?(
                t, nfields
            ))
        }
    }

    pub(in crate::plugin::tables) fn get_table_field(
        &self,
        t: *mut ss_plugin_table_t,
        name: *const ::std::os::raw::c_char,
        data_type: ss_plugin_state_type,
    ) -> Result<*mut ss_plugin_table_field_t, TableError> {
        unsafe {
            Ok(self
                .fields_ext
                .get_table_field
                .ok_or(BadVtable("get_table_field"))?(
                t, name, data_type
            ))
        }
    }

    pub(in crate::plugin::tables) fn add_table_field(
        &self,
        t: *mut ss_plugin_table_t,
        name: *const ::std::os::raw::c_char,
        data_type: ss_plugin_state_type,
    ) -> Result<*mut ss_plugin_table_field_t, TableError> {
        unsafe {
            Ok(self
                .fields_ext
                .add_table_field
                .ok_or(BadVtable("add_table_field"))?(
                t, name, data_type
            ))
        }
    }
}
