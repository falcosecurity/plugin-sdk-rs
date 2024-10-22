use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::vtable::TableError;
use crate::plugin::tables::vtable::TableError::BadVtable;
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_rc, ss_plugin_state_data, ss_plugin_table_entry_t,
    ss_plugin_table_field_t, ss_plugin_table_iterator_func_t, ss_plugin_table_iterator_state_t,
    ss_plugin_table_reader_vtable_ext, ss_plugin_table_t,
};
use std::marker::PhantomData;

/// A vtable containing table read access methods
///
/// It's used as a token to prove you're allowed to read tables in a particular context.
/// The default implementation is [`crate::tables::LazyTableReader`].
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

    /// Validate all vtable entries and skip further NULL checks
    ///
    /// This method validates all possible vtable methods to make future
    /// table accesses faster. If your plugin method does more than a few
    /// (say, 10) calls to methods that take a `TableReader`, it might be
    /// faster to get a `ValidatedTableReader`
    pub fn validate(&self) -> Result<ValidatedTableReader, TableError> {
        Ok(ValidatedTableReader {
            get_table_name: self
                .reader_ext
                .get_table_name
                .ok_or(BadVtable("get_table_name"))?,
            get_table_size: self
                .reader_ext
                .get_table_size
                .ok_or(BadVtable("get_table_size"))?,
            get_table_entry: self
                .reader_ext
                .get_table_entry
                .ok_or(BadVtable("get_table_entry"))?,
            read_entry_field: self
                .reader_ext
                .read_entry_field
                .ok_or(BadVtable("read_entry_field"))?,
            release_table_entry: self
                .reader_ext
                .release_table_entry
                .ok_or(BadVtable("release_table_entry"))?,
            iterate_entries: self
                .reader_ext
                .iterate_entries
                .ok_or(BadVtable("iterate_entries"))?,
            last_error: self.last_error.clone(),
            lifetime: PhantomData,
        })
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

/// A TableReader that performs validation when created, with no subsequent checks
///
/// This implementation has some overhead when creating, but all subsequent table accesses
/// should be ever so slightly faster due to skipped NULL checks.
#[derive(Debug)]
pub struct ValidatedTableReader<'t> {
    pub(in crate::plugin::tables) get_table_name:
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t) -> *const ::std::os::raw::c_char,
    pub(in crate::plugin::tables) get_table_size:
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t) -> u64,
    pub(in crate::plugin::tables) get_table_entry:
        unsafe extern "C-unwind" fn(
            t: *mut ss_plugin_table_t,
            key: *const ss_plugin_state_data,
        ) -> *mut ss_plugin_table_entry_t,
    pub(in crate::plugin::tables) read_entry_field: unsafe extern "C-unwind" fn(
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
        f: *const ss_plugin_table_field_t,
        out: *mut ss_plugin_state_data,
    )
        -> ss_plugin_rc,
    pub(in crate::plugin::tables) release_table_entry:
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
    pub(in crate::plugin::tables) iterate_entries: unsafe extern "C-unwind" fn(
        t: *mut ss_plugin_table_t,
        it: ss_plugin_table_iterator_func_t,
        s: *mut ss_plugin_table_iterator_state_t,
    )
        -> ss_plugin_bool,

    pub(in crate::plugin::tables) last_error: LastError,
    lifetime: PhantomData<&'t ()>,
}

impl<'t> private::TableReaderImpl for ValidatedTableReader<'t> {
    type Error = std::convert::Infallible;

    unsafe fn get_table_name(
        &self,
        t: *mut ss_plugin_table_t,
    ) -> Result<*const ::std::os::raw::c_char, Self::Error> {
        unsafe { Ok((self.get_table_name)(t)) }
    }

    unsafe fn get_table_size(&self, t: *mut ss_plugin_table_t) -> Result<u64, Self::Error> {
        unsafe { Ok((self.get_table_size)(t)) }
    }

    unsafe fn get_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
    ) -> Result<*mut ss_plugin_table_entry_t, Self::Error> {
        unsafe { Ok((self.get_table_entry)(t, key)) }
    }

    unsafe fn read_entry_field(
        &self,
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
        f: *const ss_plugin_table_field_t,
        out: *mut ss_plugin_state_data,
    ) -> Result<ss_plugin_rc, Self::Error> {
        unsafe { Ok((self.read_entry_field)(t, e, f, out)) }
    }

    fn release_table_entry_fn(
        &self,
    ) -> Option<unsafe extern "C-unwind" fn(*mut ss_plugin_table_t, *mut ss_plugin_table_entry_t)>
    {
        Some(self.release_table_entry)
    }

    fn iterate_entries_fn(
        &self,
    ) -> Result<
        unsafe extern "C-unwind" fn(
            *mut ss_plugin_table_t,
            ss_plugin_table_iterator_func_t,
            *mut ss_plugin_table_iterator_state_t,
        ) -> ss_plugin_bool,
        Self::Error,
    > {
        Ok(self.iterate_entries)
    }

    fn last_error(&self) -> &LastError {
        &self.last_error
    }
}
