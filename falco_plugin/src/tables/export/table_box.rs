use crate::tables::export::entry::extensible::ExtensibleEntry;
use crate::tables::export::table::{TableData, TableEntryType};
use crate::tables::export::traits::{Entry, TableMetadata};
use crate::tables::export::{FieldRef, HasMetadata, RefShared};
use crate::tables::{FieldTypeId, Key};
use falco_plugin_api::{ss_plugin_state_data, ss_plugin_table_fieldinfo, ss_plugin_table_input};
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

/// # A table exported to other plugins
///
/// An instance of this type can be exposed to other plugins via
/// [`tables::TablesInput::add_table`](`crate::tables::TablesInput::add_table`)
///
/// The generic parameters are: key type and entry type. The key type is anything
/// usable as a table key, while the entry type is a type that can be stored in the table.
/// You can obtain such a type by `#[derive]`ing Entry on a struct describing all the table fields.
///
/// Supported key types include:
/// - integer types (u8/i8, u16/i16, u32/i32, u64/i64)
/// - [`crate::tables::import::Bool`] (an API equivalent of bool)
/// - &CStr (spelled as just `CStr` when used as a generic argument)
///
/// See [`crate::tables::export`] for details.
///
/// The implementation is thread-safe when the `thread-safe-tables` feature is enabled.
///
/// Internally, this uses `NonNull` instead of `Box` to avoid Miri's Stacked Borrows
/// transitive retagging, which would conflict with FFI callbacks that access the table
/// through raw pointers.
pub struct Table<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    ptr: NonNull<TableData<K, E>>,
}

impl<K, E> Table<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    /// Wrap a `TableData` into a `Table`.
    pub(crate) fn wrap(value: TableData<K, E>) -> Self {
        let ptr = Box::into_raw(Box::new(value));
        // SAFETY: Box::into_raw never returns null
        Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }

    /// Returns a raw mutable pointer to the contained data without creating a reference.
    pub(crate) fn as_mut_ptr(this: &Self) -> *mut TableData<K, E> {
        this.ptr.as_ptr()
    }

    /// Get or create the vtable for this table, for use in FFI.
    pub(crate) fn get_vtable(&self) -> *mut ss_plugin_table_input {
        let table_ptr = Self::as_mut_ptr(self);
        (**self).get_vtable_with_ptr(table_ptr)
    }

    /// Create a new table
    pub fn new(name: &'static CStr) -> Result<Self, anyhow::Error> {
        Ok(Self::wrap(TableData::new(name)?))
    }

    /// Create a new table using provided metadata
    ///
    /// This is only expected to be used by the derive macro.
    pub fn new_with_metadata(
        tag: &'static CStr,
        metadata: &<Self as HasMetadata>::Metadata,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self::wrap(TableData::new_with_metadata(tag, metadata)?))
    }

    /// Get an accessor to the underlying data
    ///
    /// This method returns a reference to the underlying BTreeMap, containing all the table's data.
    /// It can be useful for:
    /// - accessing the table from a different thread (with the `thread-safe-tables` feature enabled)
    /// - bypassing the table API for convenience or more control over locking
    ///
    /// To actually access the BTreeMap, you first need to lock the returned object for reading
    /// (`data.read()`) or writing (`data.write()`).
    pub fn data(&self) -> RefShared<BTreeMap<K, RefShared<ExtensibleEntry<E>>>> {
        (**self).data()
    }

    /// Return the table name.
    pub fn name(&self) -> &'static CStr {
        (**self).name()
    }

    /// Return the number of entries in the table.
    pub fn size(&self) -> usize {
        (**self).size()
    }

    /// Get an entry corresponding to a particular key.
    pub fn lookup<Q>(&self, key: &Q) -> Option<TableEntryType<E>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        (**self).lookup(key)
    }

    /// Get the value for a field in an entry.
    pub fn get_field_value(
        &self,
        entry: &TableEntryType<E>,
        field: &crate::tables::export::field_descriptor::FieldDescriptor,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        (**self).get_field_value(entry, field, out)
    }

    /// Execute a closure on all entries in the table with read-only access.
    ///
    /// The iteration continues until all entries are visited or the closure returns false.
    // TODO(upstream) the closure cannot store away the entry but we could use explicit docs
    pub fn iterate_entries<F>(&mut self, func: F) -> bool
    where
        F: FnMut(&mut TableEntryType<E>) -> bool,
    {
        (**self).iterate_entries(func)
    }

    /// Remove all entries from the table.
    pub fn clear(&mut self) {
        (**self).clear()
    }

    /// Erase an entry by key.
    pub fn erase<Q>(&mut self, key: &Q) -> Option<TableEntryType<E>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        (**self).erase(key)
    }

    /// Create a new table entry.
    ///
    /// This is a detached entry that can be later inserted into the table using [`Table::insert`].
    pub fn create_entry(&self) -> Result<TableEntryType<E>, anyhow::Error> {
        (**self).create_entry()
    }

    /// Return a closure for creating table entries
    ///
    /// The `Table` object itself cannot be shared between threads safely even with
    /// the `thread-safe-tables` feature enabled, but almost full functionality can be achieved
    /// using two objects that can:
    /// 1. The underlying BTreeMap, obtained from [Table::data]
    /// 2. A closure capable of creating a new entry (returned from this function)
    ///
    /// The only functionality missing is listing table fields, and until a use case comes along,
    /// it's likely to remain unimplemented.
    ///
    /// The entry obtained by calling the closure returned from `create_entry_fn` can be later
    /// inserted into the table e.g. by calling [BTreeMap::insert].
    ///
    /// To actually access the entry's fields, you first need to lock the returned object for reading
    /// (`data.read()`) or writing (`data.write()`).
    pub fn create_entry_fn(
        &self,
    ) -> impl Fn() -> Result<RefShared<ExtensibleEntry<E>>, anyhow::Error> + use<K, E> {
        (**self).create_entry_fn()
    }

    /// Attach an entry to a table key
    pub fn insert<Q>(&mut self, key: &Q, entry: TableEntryType<E>) -> Option<TableEntryType<E>>
    where
        K: Borrow<Q>,
        Q: Ord + ToOwned<Owned = K> + ?Sized,
    {
        (**self).insert(key, entry)
    }

    /// Write a value to a field of an entry
    pub fn write(
        &self,
        entry: &mut TableEntryType<E>,
        field: &crate::tables::export::field_descriptor::FieldDescriptor,
        value: &ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        (**self).write(entry, field, value)
    }

    /// Return a list of fields as a slice of raw FFI objects
    pub fn list_fields(&mut self) -> &[ss_plugin_table_fieldinfo] {
        (**self).list_fields()
    }

    /// Return a field descriptor for a particular field
    ///
    /// The requested `field_type` must match the actual type of the field
    pub fn get_field(&self, name: &CStr, field_type: FieldTypeId) -> Option<FieldRef> {
        (**self).get_field(name, field_type)
    }

    /// Add a new field to the table
    pub fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<FieldRef> {
        (**self).add_field(name, field_type, read_only)
    }
}

impl<K, E> Deref for Table<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    type Target = TableData<K, E>;
    fn deref(&self) -> &TableData<K, E> {
        // SAFETY: the pointer is valid as long as self is alive
        unsafe { self.ptr.as_ref() }
    }
}

impl<K, E> DerefMut for Table<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    fn deref_mut(&mut self) -> &mut TableData<K, E> {
        // SAFETY: the pointer is valid as long as self is alive and we have &mut self
        unsafe { self.ptr.as_mut() }
    }
}

impl<K, E> Drop for Table<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    fn drop(&mut self) {
        // SAFETY: we own the allocation and it hasn't been freed
        unsafe {
            drop(Box::from_raw(self.ptr.as_ptr()));
        }
    }
}

impl<K, E> Debug for Table<K, E>
where
    K: Key + Ord + Debug,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry + Debug,
    E::Metadata: TableMetadata + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        (**self).fmt(f)
    }
}

// SAFETY: Table has the same semantics as Box
unsafe impl<K, E> Send for Table<K, E>
where
    K: Key + Ord + Send,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry + Send,
    E::Metadata: TableMetadata,
{
}
unsafe impl<K, E> Sync for Table<K, E>
where
    K: Key + Ord + Sync,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry + Sync,
    E::Metadata: TableMetadata,
{
}
