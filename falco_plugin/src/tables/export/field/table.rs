use crate::tables::export::entry::table_metadata::extensible::ExtensibleEntryMetadata;
use crate::tables::export::entry::table_metadata::traits::TableMetadata;
use crate::tables::export::entry::traits::Entry;
use crate::tables::export::metadata::HasMetadata;
use crate::tables::export::ref_shared::RefShared;
use crate::tables::export::table::Table;
use crate::tables::Key;
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
