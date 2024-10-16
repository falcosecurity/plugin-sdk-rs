use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::vtable::TableError;
use crate::plugin::tables::vtable::TableError::BadVtable;
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_rc, ss_plugin_state_data, ss_plugin_table_entry_t,
    ss_plugin_table_field_t, ss_plugin_table_iterator_func_t, ss_plugin_table_iterator_state_t,
    ss_plugin_table_reader_vtable_ext, ss_plugin_table_t,
};

/// A vtable containing table read access methods
///
/// It's used as a token to prove you're allowed to read tables in a particular context
#[derive(Debug)]
pub struct TableReader<'t> {
    reader_ext: &'t ss_plugin_table_reader_vtable_ext,
    pub(in crate::plugin::tables) last_error: LastError,
}

impl<'t> TableReader<'t> {
    pub(crate) fn try_from(
        reader_ext: &'t ss_plugin_table_reader_vtable_ext,
        last_error: LastError,
    ) -> Result<Self, TableError> {
        Ok(TableReader {
            reader_ext,
            last_error,
        })
    }

    pub(in crate::plugin::tables) fn get_table_name(
        &self,
        t: *mut ss_plugin_table_t,
    ) -> Result<*const ::std::os::raw::c_char, TableError> {
        Ok(unsafe {
            self.reader_ext
                .get_table_name
                .ok_or(BadVtable("get_table_name"))?(t)
        })
    }

    pub(in crate::plugin::tables) fn get_table_size(
        &self,
        t: *mut ss_plugin_table_t,
    ) -> Result<u64, TableError> {
        Ok(unsafe {
            self.reader_ext
                .get_table_size
                .ok_or(BadVtable("get_table_size"))?(t)
        })
    }

    pub(in crate::plugin::tables) fn get_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
    ) -> Result<*mut ss_plugin_table_entry_t, TableError> {
        Ok(unsafe {
            self.reader_ext
                .get_table_entry
                .ok_or(BadVtable("get_table_entry"))?(t, key)
        })
    }

    pub(in crate::plugin::tables) fn read_entry_field(
        &self,
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
        f: *const ss_plugin_table_field_t,
        out: *mut ss_plugin_state_data,
    ) -> Result<ss_plugin_rc, TableError> {
        Ok(unsafe {
            self.reader_ext
                .read_entry_field
                .ok_or(BadVtable("read_entry_field"))?(t, e, f, out)
        })
    }

    pub(in crate::plugin::tables) fn release_table_entry_fn(
        &self,
    ) -> Option<
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
    > {
        self.reader_ext.release_table_entry
    }

    pub(in crate::plugin::tables) fn iterate_entries_fn(
        &self,
    ) -> Result<
        unsafe extern "C-unwind" fn(
            t: *mut ss_plugin_table_t,
            it: ss_plugin_table_iterator_func_t,
            s: *mut ss_plugin_table_iterator_state_t,
        ) -> ss_plugin_bool,
        TableError,
    > {
        self.reader_ext
            .iterate_entries
            .ok_or(BadVtable("iterate_entries"))
    }
}
