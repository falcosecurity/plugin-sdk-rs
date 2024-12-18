use crate::plugin::exported_tables::entry::table_metadata::traits::TableMetadata;
use crate::plugin::exported_tables::entry::traits::Entry;
use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::exported_tables::field_value::traits::FieldValue;
use crate::plugin::exported_tables::field_value::traits::{seal, StaticField};
use crate::plugin::exported_tables::table::Table;
use crate::plugin::tables::data::{FieldTypeId, Key};
use falco_plugin_api::ss_plugin_state_data;
use std::borrow::Borrow;

impl<K, E> seal::Sealed for Box<Table<K, E>>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata + Clone,
{
}

impl<K, E> FieldValue for Box<Table<K, E>>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata + Clone,
{
    fn to_data(
        &self,
        out: &mut ss_plugin_state_data,
        type_id: FieldTypeId,
    ) -> Result<(), anyhow::Error> {
        if type_id != FieldTypeId::Table {
            anyhow::bail!("Type mismatch, requested {:?}, got table", type_id)
        }
        let vtable = self.get_boxed_vtable();

        out.table = vtable.cast();
        Ok(())
    }
}

impl<K, E> StaticField for Box<Table<K, E>>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata + Clone,
{
    const TYPE_ID: FieldTypeId = FieldTypeId::Table;
    const READONLY: bool = true;
}

impl<K, E> TryFrom<DynamicFieldValue> for Box<Table<K, E>>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata + Clone,
{
    type Error = anyhow::Error;

    fn try_from(_value: DynamicFieldValue) -> Result<Self, Self::Error> {
        anyhow::bail!("Table-valued fields cannot be set")
    }
}
