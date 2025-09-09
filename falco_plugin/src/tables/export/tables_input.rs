use crate::error::as_result::{AsResult, WithLastError};
use crate::tables::export::traits::{Entry, TableMetadata};
use crate::tables::export::wrappers::{fields_vtable, reader_vtable, writer_vtable};
use crate::tables::export::Table;
use crate::tables::{Key, TablesInput};
use falco_plugin_api::{
    ss_plugin_state_type, ss_plugin_table_fields_vtable, ss_plugin_table_input,
    ss_plugin_table_reader_vtable, ss_plugin_table_writer_vtable,
};
use std::borrow::Borrow;

impl TablesInput<'_> {
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
