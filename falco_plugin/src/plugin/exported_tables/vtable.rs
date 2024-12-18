use crate::plugin::exported_tables::entry::table_metadata::traits::TableMetadata;
use crate::plugin::exported_tables::entry::traits::Entry;
use crate::plugin::exported_tables::wrappers::{fields_vtable, reader_vtable, writer_vtable};
use crate::plugin::tables::data::Key;
use crate::tables::export::Table;
use falco_plugin_api::{
    ss_plugin_state_type, ss_plugin_table_fields_vtable, ss_plugin_table_fields_vtable_ext,
    ss_plugin_table_input, ss_plugin_table_reader_vtable, ss_plugin_table_reader_vtable_ext,
    ss_plugin_table_writer_vtable, ss_plugin_table_writer_vtable_ext,
};
use std::borrow::Borrow;

pub(crate) struct Vtable {
    pub(crate) input: ss_plugin_table_input,
    reader_ext: ss_plugin_table_reader_vtable_ext,
    writer_ext: ss_plugin_table_writer_vtable_ext,
    fields_ext: ss_plugin_table_fields_vtable_ext,
}

impl<K, E> Table<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    #[allow(clippy::borrowed_box)]
    pub(crate) fn get_boxed_vtable(self: &Box<Self>) -> *mut ss_plugin_table_input {
        let table_ptr = self.as_ref() as *const Table<K, E> as *mut Table<K, E>;
        let mut vtable_place = self.vtable.write();

        if let Some(ref mut vtable) = *vtable_place {
            // the ss_plugin_table_t value should never change
            debug_assert_eq!(vtable.input.table, table_ptr.cast());
            return &mut vtable.input as *mut _;
        }

        let reader_vtable_ext = reader_vtable::<K, E>();
        let writer_vtable_ext = writer_vtable::<K, E>();
        let fields_vtable_ext = fields_vtable::<K, E>();

        let table_input = ss_plugin_table_input {
            name: self.name().as_ptr(),
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
            reader_ext: std::ptr::null_mut(),
            writer_ext: std::ptr::null_mut(),
            fields_ext: std::ptr::null_mut(),
        };

        let mut vtable = Box::new(Vtable {
            input: table_input,
            reader_ext: reader_vtable_ext,
            writer_ext: writer_vtable_ext,
            fields_ext: fields_vtable_ext,
        });

        // we can init these fields only now, when the target struct is allocated on the heap
        vtable.input.reader_ext = &mut vtable.reader_ext as *mut _;
        vtable.input.writer_ext = &mut vtable.writer_ext as *mut _;
        vtable.input.fields_ext = &mut vtable.fields_ext as *mut _;

        let ptr = &mut vtable.input as *mut _;
        *vtable_place = Some(vtable);

        ptr
    }
}
