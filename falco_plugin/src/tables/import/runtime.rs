use crate::tables::import::entry::Entry;
use crate::tables::import::table::raw::RawTable;
use crate::tables::import::traits::TableMetadata;
use crate::tables::TablesInput;
use std::marker::PhantomData;

/// A table entry with no predefined fields
///
/// It takes a tag struct as a type to distinguish between entries from different
/// tables at compile time (runtime checks are also done on a best-effort basis)
pub type RuntimeEntry<T> = Entry<NoMetadata<T>>;

#[derive(Debug)]
pub struct NoMetadata<T> {
    tag: PhantomData<T>,
}

impl<T> Clone for NoMetadata<T> {
    fn clone(&self) -> Self {
        Self { tag: PhantomData }
    }
}

impl<T> TableMetadata for NoMetadata<T> {
    fn new(_raw_table: &RawTable, _tables_input: &TablesInput) -> Result<Self, anyhow::Error> {
        Ok(Self { tag: PhantomData })
    }
}

impl<'a, T, U> From<&'a NoMetadata<T>> for NoMetadata<U> {
    fn from(_value: &'a NoMetadata<T>) -> Self {
        Self { tag: PhantomData }
    }
}

impl<'a, T> From<&'a NoMetadata<T>> for () {
    fn from(_value: &'a NoMetadata<T>) -> Self {}
}
