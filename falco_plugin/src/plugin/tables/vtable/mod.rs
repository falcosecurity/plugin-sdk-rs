use crate::plugin::error::as_result::{AsResult, WithLastError};
use crate::plugin::error::last_error::LastError;
use crate::plugin::exported_tables::entry::table_metadata::traits::TableMetadata;
use crate::plugin::exported_tables::entry::traits::Entry;
use crate::plugin::exported_tables::table::Table;
use crate::plugin::exported_tables::wrappers::{fields_vtable, reader_vtable, writer_vtable};
use crate::plugin::tables::data::Key;
use crate::plugin::tables::table::raw::RawTable;
use crate::plugin::tables::traits::{TableAccess, TableMetadata as ImportedTableMetadata};
use falco_plugin_api::{
    ss_plugin_init_input, ss_plugin_owner_t, ss_plugin_rc, ss_plugin_state_type,
    ss_plugin_table_fields_vtable, ss_plugin_table_info, ss_plugin_table_input,
    ss_plugin_table_reader_vtable, ss_plugin_table_t, ss_plugin_table_writer_vtable,
};
use std::borrow::Borrow;
use std::ffi::CStr;
use thiserror::Error;

pub mod fields;
pub mod reader;
pub mod writer;

use crate::tables::LazyTableReader;
use fields::TableFields;
use writer::LazyTableWriter;

#[derive(Error, Debug)]
pub enum TableError {
    #[error("Missing entry {0} in table operations vtable")]
    BadVtable(&'static str),
}

#[derive(Debug)]
/// An object containing table-related vtables
///
/// It's used as a token to prove you're allowed to read/write tables
/// or manage their fields
pub struct TablesInput<'t> {
    owner: *mut ss_plugin_owner_t,
    pub(in crate::plugin::tables) last_error: LastError,
    pub(in crate::plugin::tables) list_tables:
        unsafe extern "C-unwind" fn(
            o: *mut ss_plugin_owner_t,
            ntables: *mut u32,
        ) -> *mut ss_plugin_table_info,
    pub(in crate::plugin::tables) get_table: unsafe extern "C-unwind" fn(
        o: *mut ss_plugin_owner_t,
        name: *const ::std::os::raw::c_char,
        key_type: ss_plugin_state_type,
    )
        -> *mut ss_plugin_table_t,
    pub(in crate::plugin::tables) add_table: unsafe extern "C-unwind" fn(
        o: *mut ss_plugin_owner_t,
        in_: *const ss_plugin_table_input,
    ) -> ss_plugin_rc,

    /// accessor object for reading tables
    pub(in crate::plugin::tables) reader_ext: LazyTableReader<'t>,

    /// accessor object for writing tables
    pub(in crate::plugin::tables) writer_ext: LazyTableWriter<'t>,

    /// accessor object for manipulating fields
    pub(in crate::plugin::tables) fields_ext: TableFields<'t>,
}

impl<'t> TablesInput<'t> {
    pub(crate) fn try_from(value: &ss_plugin_init_input) -> Result<Option<Self>, TableError> {
        if let Some(table_init_input) = unsafe { value.tables.as_ref() } {
            let reader_ext = unsafe {
                table_init_input
                    .reader_ext
                    .as_ref()
                    .ok_or(TableError::BadVtable("reader_ext"))?
            };
            let writer_ext = unsafe {
                table_init_input
                    .writer_ext
                    .as_ref()
                    .ok_or(TableError::BadVtable("writer_ext"))?
            };
            let fields_ext = unsafe {
                table_init_input
                    .fields_ext
                    .as_ref()
                    .ok_or(TableError::BadVtable("fields_ext"))?
            };

            let get_owner_last_error = value
                .get_owner_last_error
                .ok_or(TableError::BadVtable("get_owner_last_error"))?;
            let last_error = unsafe { LastError::new(value.owner, get_owner_last_error) };

            Ok(Some(TablesInput {
                owner: value.owner,
                last_error: last_error.clone(),
                list_tables: table_init_input
                    .list_tables
                    .ok_or(TableError::BadVtable("list_tables"))?,
                get_table: table_init_input
                    .get_table
                    .ok_or(TableError::BadVtable("get_table"))?,
                add_table: table_init_input
                    .add_table
                    .ok_or(TableError::BadVtable("add_table"))?,
                reader_ext: LazyTableReader::new(reader_ext, last_error.clone()),
                writer_ext: LazyTableWriter::try_from(writer_ext, last_error)?,
                fields_ext: TableFields::try_from(fields_ext)?,
            }))
        } else {
            Ok(None)
        }
    }
}

impl<'t> TablesInput<'t> {
    /// # List the available tables
    ///
    /// **Note**: this method is of limited utility in actual plugin code (you know the tables you
    /// want to access), so it returns the unmodified structure from the plugin API, including
    /// raw pointers to C-style strings. This may change later.
    pub fn list_tables(&self) -> &[ss_plugin_table_info] {
        let mut num_tables = 0u32;
        let tables = unsafe { (self.list_tables)(self.owner, &mut num_tables as *mut _) };
        if tables.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(tables, num_tables as usize) }
        }
    }

    /// # Import a table from the Falco plugin API
    ///
    /// The key type is verified by the plugin API, so this method will return
    /// an error on mismatch
    pub fn get_table<T, K>(&self, name: &CStr) -> Result<T, anyhow::Error>
    where
        T: TableAccess<Key = K>,
        K: Key,
    {
        let table = unsafe {
            (self.get_table)(
                self.owner,
                name.as_ptr().cast(),
                K::TYPE_ID as ss_plugin_state_type,
            )
        };
        if table.is_null() {
            Err(anyhow::anyhow!("Could not get table {:?}", name)).with_last_error(&self.last_error)
        } else {
            // Safety: we pass the data directly from FFI, the framework would never lie to us, right?
            let table = RawTable { table };
            let metadata = T::Metadata::new(&table, self)?;
            Ok(T::new(table, metadata, false))
        }
    }

    /// # Export a table to the Falco plugin API
    ///
    /// This method returns a Box, which you need to store in your plugin instance
    /// even if you don't intend to use the table yourself (the table is destroyed when
    /// going out of scope, which will lead to crashes in plugins using your table).
    pub fn add_table<K, E>(&self, table: Table<K, E>) -> Result<Box<Table<K, E>>, anyhow::Error>
    where
        K: Key + Ord,
        K: Borrow<<K as Key>::Borrowed>,
        <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
        E: Entry,
        E::Metadata: TableMetadata,
    {
        let mut reader_vtable_ext = reader_vtable::<K, E>();
        let mut writer_vtable_ext = writer_vtable::<K, E>();
        let mut fields_vtable_ext = fields_vtable::<K, E>();

        let mut table = Box::new(table);
        let table_ptr = table.as_mut() as *mut Table<K, E>;

        // Note: we lend the ss_plugin_table_input to the FFI api and do not need
        // to hold on to it (everything is copied out), but the name field is copied
        // as a pointer, so the name we receive must be a 'static ref
        let table_input = ss_plugin_table_input {
            name: table.name().as_ptr(),
            key_type: K::TYPE_ID as ss_plugin_state_type,
            table: table_ptr.cast(),
            reader: ss_plugin_table_reader_vtable {
                get_table_name: reader_vtable_ext.get_table_name,
                get_table_size: reader_vtable_ext.get_table_size,
                get_table_entry: reader_vtable_ext.get_table_entry,
                read_entry_field: reader_vtable_ext.read_entry_field,
            },
            writer: ss_plugin_table_writer_vtable {
                clear_table: writer_vtable_ext.clear_table,
                erase_table_entry: writer_vtable_ext.erase_table_entry,
                create_table_entry: writer_vtable_ext.create_table_entry,
                destroy_table_entry: writer_vtable_ext.destroy_table_entry,
                add_table_entry: writer_vtable_ext.add_table_entry,
                write_entry_field: writer_vtable_ext.write_entry_field,
            },
            fields: ss_plugin_table_fields_vtable {
                list_table_fields: fields_vtable_ext.list_table_fields,
                get_table_field: fields_vtable_ext.get_table_field,
                add_table_field: fields_vtable_ext.add_table_field,
            },
            reader_ext: &mut reader_vtable_ext as *mut _,
            writer_ext: &mut writer_vtable_ext as *mut _,
            fields_ext: &mut fields_vtable_ext as *mut _,
        };

        unsafe { (self.add_table)(self.owner, &table_input as *const _) }
            .as_result()
            .with_last_error(&self.last_error)?;
        Ok(table)
    }
}
