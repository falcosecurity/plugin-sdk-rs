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
pub trait TableReader: private::TableReaderImpl {}

impl<T: private::TableReaderImpl> TableReader for T {}

pub(crate) mod private {
    use super::*;
    pub trait TableReaderImpl {
        type Error: std::error::Error + Send + Sync + 'static;

        unsafe fn get_table_name(
            &self,
            t: *mut ss_plugin_table_t,
        ) -> Result<*const ::std::os::raw::c_char, Self::Error>;

        unsafe fn get_table_size(&self, t: *mut ss_plugin_table_t) -> Result<u64, Self::Error>;

        unsafe fn get_table_entry(
            &self,
            t: *mut ss_plugin_table_t,
            key: *const ss_plugin_state_data,
        ) -> Result<*mut ss_plugin_table_entry_t, Self::Error>;

        unsafe fn read_entry_field(
            &self,
            t: *mut ss_plugin_table_t,
            e: *mut ss_plugin_table_entry_t,
            f: *const ss_plugin_table_field_t,
            out: *mut ss_plugin_state_data,
        ) -> Result<ss_plugin_rc, Self::Error>;

        fn release_table_entry_fn(
            &self,
        ) -> Option<
            unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
        >;

        fn iterate_entries_fn(
            &self,
        ) -> Result<
            unsafe extern "C-unwind" fn(
                t: *mut ss_plugin_table_t,
                it: ss_plugin_table_iterator_func_t,
                s: *mut ss_plugin_table_iterator_state_t,
            ) -> ss_plugin_bool,
            Self::Error,
        >;

        fn last_error(&self) -> &LastError;
    }
}

/// A TableReader that performs validation on demand
///
/// This has no overhead when not actively using tables, but after a few accesses
/// the repeated null checks might add up
#[derive(Debug)]
pub struct LazyTableReader<'t> {
    reader_ext: &'t ss_plugin_table_reader_vtable_ext,
    pub(in crate::plugin::tables) last_error: LastError,
}

impl<'t> LazyTableReader<'t> {
    pub(crate) fn new(
        reader_ext: &'t ss_plugin_table_reader_vtable_ext,
        last_error: LastError,
    ) -> Self {
        LazyTableReader {
            reader_ext,
            last_error,
        }
    }
}

impl<'t> private::TableReaderImpl for LazyTableReader<'t> {
    type Error = TableError;

    unsafe fn get_table_name(
        &self,
        t: *mut ss_plugin_table_t,
    ) -> Result<*const ::std::os::raw::c_char, Self::Error> {
        Ok(unsafe {
            self.reader_ext
                .get_table_name
                .ok_or(BadVtable("get_table_name"))?(t)
        })
    }

    unsafe fn get_table_size(&self, t: *mut ss_plugin_table_t) -> Result<u64, Self::Error> {
        Ok(unsafe {
            self.reader_ext
                .get_table_size
                .ok_or(BadVtable("get_table_size"))?(t)
        })
    }

    unsafe fn get_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
    ) -> Result<*mut ss_plugin_table_entry_t, Self::Error> {
        Ok(unsafe {
            self.reader_ext
                .get_table_entry
                .ok_or(BadVtable("get_table_entry"))?(t, key)
        })
    }

    unsafe fn read_entry_field(
        &self,
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
        f: *const ss_plugin_table_field_t,
        out: *mut ss_plugin_state_data,
    ) -> Result<ss_plugin_rc, Self::Error> {
        Ok(unsafe {
            self.reader_ext
                .read_entry_field
                .ok_or(BadVtable("read_entry_field"))?(t, e, f, out)
        })
    }

    fn release_table_entry_fn(
        &self,
    ) -> Option<
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
    > {
        self.reader_ext.release_table_entry
    }

    fn iterate_entries_fn(
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

    fn last_error(&self) -> &LastError {
        &self.last_error
    }
}
