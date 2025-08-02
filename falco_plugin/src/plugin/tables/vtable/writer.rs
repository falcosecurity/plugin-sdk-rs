use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::vtable::TableError;
use crate::plugin::tables::vtable::TableError::BadVtable;
use falco_plugin_api::{
    ss_plugin_rc, ss_plugin_state_data, ss_plugin_table_entry_t, ss_plugin_table_field_t,
    ss_plugin_table_t, ss_plugin_table_writer_vtable_ext,
};
use std::marker::PhantomData;

/// A vtable containing table write access methods
///
/// It's used as a token to prove you're allowed to write tables in a particular context
/// The default implementation is [`crate::tables::LazyTableWriter`].
pub trait TableWriter: private::TableWriterImpl {}

impl<T: private::TableWriterImpl> TableWriter for T {}

pub(crate) mod private {
    use super::*;

    pub trait TableWriterImpl {
        type Error: std::error::Error + Send + Sync + 'static;

        unsafe fn clear_table(
            &self,
            t: *mut ss_plugin_table_t,
        ) -> Result<ss_plugin_rc, Self::Error>;

        unsafe fn erase_table_entry(
            &self,
            t: *mut ss_plugin_table_t,
            key: *const ss_plugin_state_data,
        ) -> Result<ss_plugin_rc, Self::Error>;

        unsafe fn create_table_entry(
            &self,
            t: *mut ss_plugin_table_t,
        ) -> Result<*mut ss_plugin_table_entry_t, Self::Error>;

        unsafe fn destroy_table_entry(
            &self,
            t: *mut ss_plugin_table_t,
            e: *mut ss_plugin_table_entry_t,
        );

        fn destroy_table_entry_fn(
            &self,
        ) -> Option<
            unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
        >;

        unsafe fn add_table_entry(
            &self,
            t: *mut ss_plugin_table_t,
            key: *const ss_plugin_state_data,
            entry: *mut ss_plugin_table_entry_t,
        ) -> Result<*mut ss_plugin_table_entry_t, Self::Error>;

        unsafe fn write_entry_field(
            &self,
            t: *mut ss_plugin_table_t,
            e: *mut ss_plugin_table_entry_t,
            f: *const ss_plugin_table_field_t,
            in_: *const ss_plugin_state_data,
        ) -> Result<ss_plugin_rc, Self::Error>;

        fn last_error(&self) -> &LastError;
    }
}

/// A TableWriter that performs validation on demand
///
/// This has no overhead when not actively using tables, but after a few accesses
/// the repeated null checks might add up
#[derive(Debug)]
pub struct LazyTableWriter<'t> {
    writer_ext: &'t ss_plugin_table_writer_vtable_ext,
    pub(in crate::plugin::tables) last_error: LastError,
}

impl<'t> LazyTableWriter<'t> {
    pub(crate) fn try_from(
        writer_ext: &'t ss_plugin_table_writer_vtable_ext,
        last_error: LastError,
    ) -> Result<Self, TableError> {
        Ok(LazyTableWriter {
            writer_ext,
            last_error,
        })
    }

    /// Validate all vtable entries and skip further NULL checks
    ///
    /// This method validates all possible vtable methods to make future
    /// table accesses faster. If your plugin method does more than a few
    /// (say, 10) calls to methods that take a `TableWriter`, it might be
    /// faster to get a `ValidatedTableWriter`
    pub fn validate(&self) -> Result<ValidatedTableWriter<'_>, TableError> {
        Ok(ValidatedTableWriter {
            clear_table: self
                .writer_ext
                .clear_table
                .ok_or(BadVtable("clear_table"))?,
            erase_table_entry: self
                .writer_ext
                .erase_table_entry
                .ok_or(BadVtable("erase_table_entry"))?,
            create_table_entry: self
                .writer_ext
                .create_table_entry
                .ok_or(BadVtable("create_table_entry"))?,
            destroy_table_entry: self
                .writer_ext
                .destroy_table_entry
                .ok_or(BadVtable("destroy_table_entry"))?,
            add_table_entry: self
                .writer_ext
                .add_table_entry
                .ok_or(BadVtable("add_table_entry"))?,
            write_entry_field: self
                .writer_ext
                .write_entry_field
                .ok_or(BadVtable("write_entry_field"))?,
            last_error: self.last_error.clone(),
            lifetime: PhantomData,
        })
    }
}

impl private::TableWriterImpl for LazyTableWriter<'_> {
    type Error = TableError;

    unsafe fn clear_table(&self, t: *mut ss_plugin_table_t) -> Result<ss_plugin_rc, TableError> {
        unsafe {
            Ok(self
                .writer_ext
                .clear_table
                .ok_or(BadVtable("clear_table"))?(t))
        }
    }

    unsafe fn erase_table_entry(
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

    unsafe fn create_table_entry(
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

    unsafe fn destroy_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
    ) {
        let Some(destroy_table_entry) = self.writer_ext.destroy_table_entry else {
            return;
        };

        unsafe { destroy_table_entry(t, e) }
    }

    fn destroy_table_entry_fn(
        &self,
    ) -> Option<
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
    > {
        self.writer_ext.destroy_table_entry
    }

    unsafe fn add_table_entry(
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

    unsafe fn write_entry_field(
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

    fn last_error(&self) -> &LastError {
        &self.last_error
    }
}

/// A vtable containing table write access methods
///
/// It's used as a token to prove you're allowed to write tables in a particular context
#[derive(Debug)]
pub struct ValidatedTableWriter<'t> {
    clear_table: unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t) -> ss_plugin_rc,
    erase_table_entry: unsafe extern "C-unwind" fn(
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
    ) -> ss_plugin_rc,
    create_table_entry:
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t) -> *mut ss_plugin_table_entry_t,
    destroy_table_entry:
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
    add_table_entry: unsafe extern "C-unwind" fn(
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
        entry: *mut ss_plugin_table_entry_t,
    ) -> *mut ss_plugin_table_entry_t,
    write_entry_field: unsafe extern "C-unwind" fn(
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
        f: *const ss_plugin_table_field_t,
        in_: *const ss_plugin_state_data,
    ) -> ss_plugin_rc,

    pub(in crate::plugin::tables) last_error: LastError,
    lifetime: PhantomData<&'t ()>,
}

impl private::TableWriterImpl for ValidatedTableWriter<'_> {
    type Error = std::convert::Infallible;

    unsafe fn clear_table(&self, t: *mut ss_plugin_table_t) -> Result<ss_plugin_rc, Self::Error> {
        unsafe { Ok((self.clear_table)(t)) }
    }

    unsafe fn erase_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
    ) -> Result<ss_plugin_rc, Self::Error> {
        unsafe { Ok((self.erase_table_entry)(t, key)) }
    }

    unsafe fn create_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
    ) -> Result<*mut ss_plugin_table_entry_t, Self::Error> {
        unsafe { Ok((self.create_table_entry)(t)) }
    }

    unsafe fn destroy_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
    ) {
        unsafe { (self.destroy_table_entry)(t, e) }
    }

    fn destroy_table_entry_fn(
        &self,
    ) -> Option<
        unsafe extern "C-unwind" fn(t: *mut ss_plugin_table_t, e: *mut ss_plugin_table_entry_t),
    > {
        Some(self.destroy_table_entry)
    }

    unsafe fn add_table_entry(
        &self,
        t: *mut ss_plugin_table_t,
        key: *const ss_plugin_state_data,
        entry: *mut ss_plugin_table_entry_t,
    ) -> Result<*mut ss_plugin_table_entry_t, Self::Error> {
        unsafe { Ok((self.add_table_entry)(t, key, entry)) }
    }

    unsafe fn write_entry_field(
        &self,
        t: *mut ss_plugin_table_t,
        e: *mut ss_plugin_table_entry_t,
        f: *const ss_plugin_table_field_t,
        in_: *const ss_plugin_state_data,
    ) -> Result<ss_plugin_rc, Self::Error> {
        unsafe { Ok((self.write_entry_field)(t, e, f, in_)) }
    }

    fn last_error(&self) -> &LastError {
        &self.last_error
    }
}
