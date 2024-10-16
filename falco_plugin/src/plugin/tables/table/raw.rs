use crate::plugin::error::as_result::{AsResult, WithLastError};
use crate::plugin::tables::data::{FieldTypeId, Key, Value};
use crate::plugin::tables::entry::raw::RawEntry;
use crate::plugin::tables::field::raw::RawField;
use crate::plugin::tables::traits::TableMetadata;
use crate::plugin::tables::vtable::{TableError, TableFields};
use crate::plugin::tables::vtable::{TableReader, TableWriter, TablesInput};
use crate::strings::from_ptr::{try_str_from_ptr_with_lifetime, FromPtrError};
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_state_data, ss_plugin_state_type,
    ss_plugin_table_entry_t, ss_plugin_table_field_t, ss_plugin_table_fieldinfo,
    ss_plugin_table_iterator_func_t, ss_plugin_table_iterator_state_t, ss_plugin_table_t,
};
use num_traits::FromPrimitive;
use std::ffi::CStr;
use std::ops::ControlFlow;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TableNameError {
    #[error(transparent)]
    TableError(#[from] TableError),
    #[error(transparent)]
    PtrError(#[from] FromPtrError),
}

/// # A low-level representation of a table
///
/// This is a thin wrapper around the Falco plugin API and provides little type safety.
///
/// You will probably want to use [`crate::tables::import::Table`] instead.
#[derive(Debug)]
pub struct RawTable {
    pub(crate) table: *mut ss_plugin_table_t,
}

impl RawTable {
    /// # List the available fields
    ///
    /// **Note**: this method is of limited utility in actual plugin code (you know the fields you
    /// want to access), so it returns the unmodified structure from the plugin API, including
    /// raw pointers to C-style strings. This may change later.
    pub fn list_fields(&self, fields_vtable: &TableFields) -> &[ss_plugin_table_fieldinfo] {
        let mut num_fields = 0u32;
        let fields =
            unsafe { (fields_vtable.list_table_fields)(self.table, &mut num_fields as *mut _) };
        if fields.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(fields, num_fields as usize) }
        }
    }

    /// # Get a table field by name
    ///
    /// The field must exist in the table and must be of the type `V`, otherwise an error
    /// will be returned.
    ///
    /// Note that you must not use fields with tables they did not come from. When using fields
    /// returned from this method, no such validation happens.
    pub fn get_field<V: Value + ?Sized>(
        &self,
        tables_input: &TablesInput,
        name: &CStr,
    ) -> Result<RawField<V>, anyhow::Error> {
        let raw_field = unsafe {
            let field = (tables_input.fields_ext.get_table_field)(
                self.table,
                name.as_ptr().cast(),
                V::TYPE_ID as ss_plugin_state_type,
            );
            field
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Failed to get table field {:?}", name))
                .with_last_error(&tables_input.last_error)?;
            field
        };

        let assoc = unsafe { V::get_assoc_from_raw_table(self, raw_field, tables_input) }?;

        Ok(RawField {
            field: raw_field,
            assoc_data: assoc,
        })
    }

    /// # Add a table field
    ///
    /// The field will have the specified name and the type is derived from the generic argument.
    ///
    /// Note that you must not use fields with tables they did not come from. When using fields
    /// returned from this method, no such validation happens.
    pub fn add_field<V: Value<AssocData = ()> + ?Sized>(
        &self,
        tables_input: &TablesInput,
        name: &CStr,
    ) -> Result<RawField<V>, anyhow::Error> {
        let raw_field = unsafe {
            let field = (tables_input.fields_ext.add_table_field)(
                self.table,
                name.as_ptr().cast(),
                V::TYPE_ID as ss_plugin_state_type,
            );
            field
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Failed to add table field {:?}", name))
                .with_last_error(&tables_input.last_error)?;
            field
        };

        Ok(RawField {
            field: raw_field,
            assoc_data: (),
        })
    }

    /// # Look up an entry in `table` corresponding to `key`
    pub fn get_entry<K: Key>(
        &self,
        reader_vtable: &TableReader,
        key: &K,
    ) -> Result<RawEntry, anyhow::Error> {
        let input = unsafe { &*(self.table as *mut falco_plugin_api::ss_plugin_table_input) };
        if input.key_type != K::TYPE_ID as ss_plugin_state_type {
            anyhow::bail!(
                "Bad key type, requested {:?}, table has {:?}",
                K::TYPE_ID,
                FieldTypeId::from_u32(input.key_type),
            );
        }

        let entry = reader_vtable.get_table_entry(self.table, &key.to_data() as *const _)?;

        if entry.is_null() {
            Err(anyhow::anyhow!("table entry not found"))
        } else {
            Ok(RawEntry {
                table: self.table,
                entry: entry as *mut _,
                destructor: reader_vtable.release_table_entry_fn(),
            })
        }
    }

    /// # Erase a table entry by key
    ///
    /// # Safety
    /// The key type must be the same as actually used by the table. Using the wrong type
    /// (especially using a number if the real key type is a string) will lead to UB.
    pub unsafe fn erase<K: Key>(
        &self,
        writer_vtable: &TableWriter,
        key: &K,
    ) -> Result<(), anyhow::Error> {
        Ok(writer_vtable
            .erase_table_entry(self.table, &key.to_data() as *const _)?
            .as_result()?)
    }

    /// # Create a table entry
    ///
    /// This creates an entry that's not attached to any particular key. To insert it into
    /// the table, pass it to [`RawTable::insert`]
    pub fn create_entry(&self, writer_vtable: &TableWriter) -> Result<RawEntry, anyhow::Error> {
        let entry = writer_vtable.create_table_entry(self.table)?;

        if entry.is_null() {
            Err(anyhow::anyhow!("Failed to create table entry"))
        } else {
            Ok(RawEntry {
                table: self.table,
                entry,
                destructor: writer_vtable.destroy_table_entry_fn(),
            })
        }
    }

    /// # Insert an entry into the table
    ///
    /// This attaches an entry to a table key, making it accessible to other plugins
    ///
    /// # Safety
    /// The key type must be the same as actually used by the table. Using the wrong type
    /// (especially using a number if the real key type is a string) will lead to UB.
    pub unsafe fn insert<K: Key>(
        &self,
        reader_vtable: &TableReader,
        writer_vtable: &TableWriter,
        key: &K,
        mut entry: RawEntry,
    ) -> Result<RawEntry, anyhow::Error> {
        let ret =
            writer_vtable.add_table_entry(self.table, &key.to_data() as *const _, entry.entry)?;

        if ret.is_null() {
            Err(anyhow::anyhow!("Failed to attach entry"))
        } else {
            entry.destructor.take();
            Ok(RawEntry {
                table: self.table,
                entry: ret,
                destructor: reader_vtable.release_table_entry_fn(),
            })
        }
    }

    /// # Get the table name
    ///
    /// This method returns an error if the name cannot be represented as UTF-8
    pub fn get_name(&self, reader_vtable: &TableReader) -> Result<&str, TableNameError> {
        unsafe {
            Ok(try_str_from_ptr_with_lifetime(
                reader_vtable.get_table_name(self.table)?,
                self,
            )?)
        }
    }

    /// # Get the table size
    ///
    /// Return the number of entries in the table
    pub fn get_size(&self, reader_vtable: &TableReader) -> Result<usize, TableError> {
        Ok(reader_vtable.get_table_size(self.table)? as usize)
    }

    /// # Iterate over all entries in a table with mutable access
    ///
    /// The closure is called once for each table entry with a corresponding [`RawEntry`]
    /// object as a parameter.
    ///
    /// The iteration stops when either all entries have been processed or the closure returns
    /// [`ControlFlow::Break`].
    pub fn iter_entries_mut<F>(
        &self,
        reader_vtable: &TableReader,
        mut func: F,
    ) -> Result<ControlFlow<()>, TableError>
    where
        F: FnMut(RawEntry) -> ControlFlow<()>,
    {
        Ok(iter_inner(
            self.table,
            reader_vtable.iterate_entries_fn()?,
            move |s: *mut ss_plugin_table_entry_t| {
                // Do not call the destructor on TableEntryReader: we do not have
                // our own refcount for it, just borrowing
                let raw_entry = RawEntry {
                    table: self.table,
                    entry: s,
                    destructor: None,
                };
                func(raw_entry).is_continue()
            },
        ))
    }

    /// # Clear the table
    ///
    /// Removes all entries from the table
    pub fn clear(&self, writer_vtable: &TableWriter) -> Result<(), anyhow::Error> {
        Ok(writer_vtable.clear_table(self.table)?.as_result()?)
    }

    pub(in crate::plugin::tables) unsafe fn with_subtable<K, F, R>(
        &self,
        field: *mut ss_plugin_table_field_t,
        tables_input: &TablesInput,
        func: F,
    ) -> Result<R, anyhow::Error>
    where
        K: Key,
        F: FnOnce(&RawTable) -> R,
    {
        let entry = tables_input.writer_ext.create_table_entry(self.table)?;
        if entry.is_null() {
            anyhow::bail!("Failed to create temporary table entry");
        }

        let mut val = ss_plugin_state_data { u64_: 0 };
        let rc = tables_input.reader_ext.read_entry_field(
            self.table,
            entry,
            field,
            &mut val as *mut _,
        )?;

        if rc != ss_plugin_rc_SS_PLUGIN_SUCCESS {
            anyhow::bail!("Failed to get field value for temporary table entry")
        }

        let input = unsafe { &*(val.table as *mut falco_plugin_api::ss_plugin_table_input) };
        if input.key_type != K::TYPE_ID as ss_plugin_state_type {
            tables_input
                .writer_ext
                .destroy_table_entry(self.table, entry);
            anyhow::bail!(
                "Bad key type, requested {:?}, table has {:?}",
                K::TYPE_ID,
                FieldTypeId::from_u32(input.key_type),
            );
        }

        let raw_table = unsafe { RawTable { table: val.table } };
        let ret = func(&raw_table);
        tables_input
            .writer_ext
            .destroy_table_entry(self.table, entry);
        Ok(ret)
    }

    #[doc(hidden)]
    // this is not really intended to be called by the end user, it's just for the derive macros
    pub fn get_metadata<K: Key, M: TableMetadata, V: Value + ?Sized>(
        &self,
        field: &RawField<V>,
        tables_input: &TablesInput,
    ) -> Result<M, anyhow::Error> {
        unsafe {
            self.with_subtable::<K, _, _>(field.field, tables_input, |subtable| {
                M::new(subtable, tables_input)
            })
        }?
    }
}

fn iter_inner<F>(
    table: *mut ss_plugin_table_t,
    iterate_entries: unsafe extern "C-unwind" fn(
        *mut ss_plugin_table_t,
        it: ss_plugin_table_iterator_func_t,
        s: *mut ss_plugin_table_iterator_state_t,
    ) -> ss_plugin_bool,
    mut func: F,
) -> ControlFlow<()>
where
    F: FnMut(*mut ss_plugin_table_entry_t) -> bool,
{
    extern "C-unwind" fn iter_wrapper<WF>(
        s: *mut ss_plugin_table_iterator_state_t,
        entry: *mut ss_plugin_table_entry_t,
    ) -> ss_plugin_bool
    where
        WF: FnMut(*mut ss_plugin_table_entry_t) -> bool,
    {
        unsafe {
            let Some(closure) = (s as *mut WF).as_mut() else {
                return 0;
            };
            let res = closure(entry);
            if res {
                1
            } else {
                0
            }
        }
    }

    let finished = unsafe {
        iterate_entries(
            table,
            Some(iter_wrapper::<F>),
            &mut func as *mut _ as *mut ss_plugin_table_iterator_state_t,
        ) != 0
    };

    match finished {
        true => ControlFlow::Continue(()),
        false => ControlFlow::Break(()),
    }
}
