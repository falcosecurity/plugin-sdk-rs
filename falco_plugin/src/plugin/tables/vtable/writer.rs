use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::vtable::TableError;
use crate::plugin::tables::vtable::TableError::BadVtable;
use falco_plugin_api::{
    ss_plugin_rc, ss_plugin_state_data, ss_plugin_table_entry_t, ss_plugin_table_field_t,
    ss_plugin_table_t, ss_plugin_table_writer_vtable_ext,
};

/// A vtable containing table write access methods
///
/// It's used as a token to prove you're allowed to write tables in a particular context
#[derive(Debug)]
pub struct TableWriter<'t> {
    writer_ext: &'t ss_plugin_table_writer_vtable_ext,
    pub(in crate::plugin::tables) last_error: LastError,
}

impl<'t> TableWriter<'t> {
    pub(crate) fn try_from(
        writer_ext: &'t ss_plugin_table_writer_vtable_ext,
        last_error: LastError,
    ) -> Result<Self, TableError> {
        Ok(TableWriter {
            writer_ext,
            last_error,
        })
    }

    pub(in crate::plugin::tables) fn clear_table(
        &self,
        t: *mut ss_plugin_table_t,
    ) -> Result<ss_plugin_rc, TableError> {
        unsafe {
            Ok(self
                .writer_ext
                .clear_table
                .ok_or(BadVtable("clear_table"))?(t))
        }
    }

    pub(in crate::plugin::tables) fn erase_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
    ) -> Result<ss_plugin_rc, TableError> {
        unsafe {
            Ok(self
                .writer_ext
                .erase_table_entry
                .ok_or(BadVtable("erase_table_entry"))?(
                t, key
            ))
        }
    }

    pub(in crate::plugin::tables) fn create_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
    ) -> Result<*mut ss_plugin_table_entry_t, TableError> {
        unsafe {
            Ok(self
                .writer_ext
                .create_table_entry
                .ok_or(BadVtable("create_table_entry"))?(t))
        }
    }

    pub(in crate::plugin::tables) fn destroy_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
    ) {
        let Some(destroy_table_entry) = self.writer_ext.destroy_table_entry else {
            return;
        };

        unsafe { destroy_table_entry(t, e) }
    }

    pub(in crate::plugin::tables) fn destroy_table_entry_fn(
        &self,
    ) -> Option<
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
    > {
        self.writer_ext.destroy_table_entry
    }

    pub(in crate::plugin::tables) fn add_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
        entry: *mut ss_plugin_table_entry_t,
    ) -> Result<*mut ss_plugin_table_entry_t, TableError> {
        unsafe {
            Ok(self
                .writer_ext
                .add_table_entry
                .ok_or(BadVtable("add_table_entry"))?(
                t, key, entry
            ))
        }
    }

    pub(in crate::plugin::tables) fn write_entry_field(
        &self,
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
        f: *const ss_plugin_table_field_t,
        in_: *const ss_plugin_state_data,
    ) -> Result<ss_plugin_rc, TableError> {
        unsafe {
            Ok(self
                .writer_ext
                .write_entry_field
                .ok_or(BadVtable("write_entry_field"))?(
                t, e, f, in_
            ))
        }
    }
}
