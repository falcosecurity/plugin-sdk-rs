use crate::tables::export::entry::table_metadata::traits::TableMetadata;
use crate::tables::export::entry::traits::Entry;
use crate::tables::export::table::TableData;
use crate::tables::export::wrappers::{fields_vtable, reader_vtable, writer_vtable};
use crate::tables::Key;
use falco_plugin_api::{
    ss_plugin_state_type, ss_plugin_table_fields_vtable, ss_plugin_table_fields_vtable_ext,
    ss_plugin_table_input, ss_plugin_table_reader_vtable, ss_plugin_table_reader_vtable_ext,
    ss_plugin_table_writer_vtable, ss_plugin_table_writer_vtable_ext,
};
use std::borrow::Borrow;
use std::cell::UnsafeCell;

pub(crate) struct Vtable {
    pub(crate) inner: UnsafeCell<VtableInner>,
}

pub(crate) struct VtableInner {
    pub(crate) input: ss_plugin_table_input,
    reader_ext: ss_plugin_table_reader_vtable_ext,
    writer_ext: ss_plugin_table_writer_vtable_ext,
    fields_ext: ss_plugin_table_fields_vtable_ext,
}

impl<K, E> TableData<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    /// Get or create the vtable for this table.
    ///
    /// `table_ptr` must be a raw pointer to `self` with write provenance
    /// (e.g. from `Table::as_mut_ptr`). This is necessary because the FFI layer
    /// will use the stored pointer for mutable access.
    pub(crate) fn get_vtable_with_ptr(
        &self,
        table_ptr: *mut TableData<K, E>,
    ) -> *mut ss_plugin_table_input {
        let mut vtable_place = self.vtable.write();

        if let Some(ref vtable) = *vtable_place {
            let inner = vtable.inner.get();
            // the ss_plugin_table_t value should never change
            debug_assert_eq!(unsafe { (*inner).input.table }, table_ptr.cast());
            return unsafe { std::ptr::addr_of_mut!((*inner).input) };
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

        let vtable = Box::new(Vtable {
            inner: UnsafeCell::new(VtableInner {
                input: table_input,
                reader_ext: reader_vtable_ext,
                writer_ext: writer_vtable_ext,
                fields_ext: fields_vtable_ext,
            }),
        });

        // Store the vtable first, then set up self-referential pointers
        // through the stored Box's UnsafeCell to preserve pointer provenance.
        *vtable_place = Some(vtable);

        let inner = vtable_place.as_ref().unwrap().inner.get();
        unsafe {
            let reader_ext_ptr = std::ptr::addr_of_mut!((*inner).reader_ext);
            let writer_ext_ptr = std::ptr::addr_of_mut!((*inner).writer_ext);
            let fields_ext_ptr = std::ptr::addr_of_mut!((*inner).fields_ext);
            (*inner).input.reader_ext = reader_ext_ptr;
            (*inner).input.writer_ext = writer_ext_ptr;
            (*inner).input.fields_ext = fields_ext_ptr;
        }

        unsafe { std::ptr::addr_of_mut!((*inner).input) }
    }
}
