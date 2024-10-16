use crate::plugin::error::as_result::{AsResult, WithLastError};
use crate::plugin::tables::data::Value;
use crate::plugin::tables::field::Field;
use crate::plugin::tables::traits::{EntryWrite, TableMetadata};
use crate::plugin::tables::vtable::reader::TableReader;
use falco_plugin_api::ss_plugin_table_t;

pub(in crate::plugin::tables) mod raw;
use crate::plugin::tables::vtable::writer::TableWriter;
use raw::RawEntry;

/// # An entry in a Falco plugin table
///
/// This type wraps an opaque pointer representing an entry in a table and allows individual
/// field access (given a [`Field`] reference).
///
/// You can add methods to this type using the `#[derive(TableMetadata)]` macro.
/// See the [module documentation](`crate::tables::import`) for details.
#[derive(Debug)]
pub struct Entry<M> {
    pub(in crate::plugin::tables) raw_entry: RawEntry,
    pub(in crate::plugin::tables) table: *mut ss_plugin_table_t,
    pub(in crate::plugin::tables) metadata: M,
}

impl<M: TableMetadata + Clone> crate::plugin::tables::traits::Entry for Entry<M> {
    type Metadata = M;

    fn new(raw_entry: RawEntry, table: *mut ss_plugin_table_t, metadata: Self::Metadata) -> Self {
        Self {
            raw_entry,
            table,
            metadata,
        }
    }

    fn get_metadata(&self) -> &Self::Metadata {
        &self.metadata
    }

    fn into_raw(self) -> RawEntry {
        self.raw_entry
    }
}

impl<M> Entry<M> {
    /// Get a field value for this entry
    pub fn read_field<V: Value + ?Sized>(
        &self,
        reader: &TableReader,
        field: &Field<V, Entry<M>>,
    ) -> Result<V::Value<'_>, anyhow::Error> {
        field.validator.check(self.table)?;
        unsafe {
            self.raw_entry
                .read_field_with_assoc::<V>(reader, field.field.field, &field.field.assoc_data)
                .ok_or_else(|| anyhow::anyhow!("Could not read field value"))
                .with_last_error(&reader.last_error)
        }
    }

    /// Set a field value for this entry
    pub fn write_field<V: Value<AssocData = ()> + ?Sized>(
        &self,
        writer: &TableWriter,
        field: &Field<V, Entry<M>>,
        val: &V,
    ) -> Result<(), anyhow::Error> {
        field.validator.check(self.table)?;
        unsafe {
            self.raw_entry
                .write_field(writer, field.field.field, &val.to_data())
                .as_result()
                .with_last_error(&writer.last_error)
        }
    }
}

impl<M, V: Value<AssocData = ()> + ?Sized> EntryWrite<&Field<V, Entry<M>>, V> for Entry<M> {
    fn write_field(
        &self,
        writer: &TableWriter,
        field: &Field<V, Entry<M>>,
        val: &V,
    ) -> Result<(), anyhow::Error> {
        Entry::write_field(self, writer, field, val)
    }
}
