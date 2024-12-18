use crate::plugin::exported_tables::entry::table_metadata::extensible::ExtensibleEntryMetadata;
use crate::plugin::exported_tables::entry::table_metadata::traits::TableMetadata;
use crate::plugin::exported_tables::entry::traits::Entry;
use crate::plugin::exported_tables::metadata::HasMetadata;
use crate::plugin::exported_tables::ref_shared::RefShared;
use crate::plugin::exported_tables::table::Table;
use crate::plugin::tables::data::Key;
use anyhow::Error;
use std::borrow::Borrow;
use std::ffi::CStr;

impl<K, E> HasMetadata for Box<Table<K, E>>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    type Metadata = RefShared<ExtensibleEntryMetadata<E::Metadata>>;

    fn new_with_metadata(tag: &'static CStr, meta: &Self::Metadata) -> Result<Self, Error> {
        Ok(Box::new(Table::new_with_metadata(tag, meta)?))
    }
}
