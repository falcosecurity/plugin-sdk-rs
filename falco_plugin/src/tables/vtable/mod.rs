use crate::error::last_error::LastError;
use falco_plugin_api::{
    ss_plugin_init_input, ss_plugin_owner_t, ss_plugin_rc, ss_plugin_state_type,
    ss_plugin_table_info, ss_plugin_table_input, ss_plugin_table_t,
};
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
    pub(crate) owner: *mut ss_plugin_owner_t,
    pub(crate) last_error: LastError,
    pub(crate) list_tables: unsafe extern "C-unwind" fn(
        o: *mut ss_plugin_owner_t,
        ntables: *mut u32,
    ) -> *mut ss_plugin_table_info,
    pub(crate) get_table: unsafe extern "C-unwind" fn(
        o: *mut ss_plugin_owner_t,
        name: *const ::std::os::raw::c_char,
        key_type: ss_plugin_state_type,
    ) -> *mut ss_plugin_table_t,
    pub(crate) add_table: unsafe extern "C-unwind" fn(
        o: *mut ss_plugin_owner_t,
        in_: *const ss_plugin_table_input,
    ) -> ss_plugin_rc,

    /// accessor object for reading tables
    pub(crate) reader_ext: LazyTableReader<'t>,

    /// accessor object for writing tables
    pub(crate) writer_ext: LazyTableWriter<'t>,

    /// accessor object for manipulating fields
    pub(crate) fields_ext: TableFields<'t>,
}

impl TablesInput<'_> {
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

impl TablesInput<'_> {
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
}
