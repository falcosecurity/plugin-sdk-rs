use crate::plugin::exported_tables::entry::extensible::ExtensibleEntry;
use crate::plugin::exported_tables::entry::table_metadata::extensible::ExtensibleEntryMetadata;
use crate::plugin::exported_tables::entry::table_metadata::traits::TableMetadata;
use crate::plugin::exported_tables::entry::traits::Entry;
use crate::plugin::exported_tables::field_descriptor::{FieldDescriptor, FieldRef};
use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::exported_tables::metadata::HasMetadata;
use crate::plugin::exported_tables::metadata::Metadata;
use crate::plugin::exported_tables::ref_shared::{
    new_counted_ref, new_shared_ref, RefCounted, RefGuard, RefShared,
};
use crate::plugin::exported_tables::vtable::Vtable;
use crate::plugin::tables::data::{FieldTypeId, Key};
use crate::FailureReason;
use falco_plugin_api::{ss_plugin_state_data, ss_plugin_table_fieldinfo};
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};

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
#[must_use]
pub struct Table<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    name: &'static CStr,
    field_descriptors: Vec<ss_plugin_table_fieldinfo>,
    metadata: RefShared<ExtensibleEntryMetadata<E::Metadata>>,
    data: RefShared<BTreeMap<K, RefShared<ExtensibleEntry<E>>>>,

    pub(in crate::plugin::exported_tables) vtable: RefCounted<Option<Box<Vtable>>>,
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
        f.debug_struct("Table")
            .field("name", &self.name)
            .field("metadata", &self.metadata)
            .field("data", &self.data)
            .finish()
    }
}

type TableMetadataType<E> = RefShared<ExtensibleEntryMetadata<<E as HasMetadata>::Metadata>>;
pub(in crate::plugin::exported_tables) type TableEntryType<E> = RefGuard<ExtensibleEntry<E>>;

impl<K, E> Table<K, E>
where
    K: Key + Ord,
    K: Borrow<<K as Key>::Borrowed>,
    <K as Key>::Borrowed: Ord + ToOwned<Owned = K>,
    E: Entry,
    E::Metadata: TableMetadata,
{
    /// Create a new table using provided metadata
    ///
    /// This is only expected to be used by the derive macro.
    pub fn new_with_metadata(
        tag: &'static CStr,
        metadata: &TableMetadataType<E>,
    ) -> Result<Self, anyhow::Error> {
        let table = Self {
            name: tag,
            field_descriptors: vec![],
            metadata: metadata.clone(),
            data: new_shared_ref(BTreeMap::new()),

            vtable: new_counted_ref(None),
        };

        Ok(table)
    }

    /// Create a new table
    pub fn new(name: &'static CStr) -> Result<Self, anyhow::Error> {
        Ok(Self {
            name,
            field_descriptors: vec![],
            metadata: new_shared_ref(ExtensibleEntryMetadata::new()?),
            data: new_shared_ref(BTreeMap::new()),

            vtable: new_counted_ref(None),
        })
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
        self.data.clone()
    }

    /// Return the table name.
    pub fn name(&self) -> &'static CStr {
        self.name
    }

    /// Return the number of entries in the table.
    pub fn size(&self) -> usize {
        self.data.read().len()
    }

    /// Get an entry corresponding to a particular key.
    pub fn lookup<Q>(&self, key: &Q) -> Option<TableEntryType<E>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        Some(self.data.read().get(key)?.write_arc())
    }

    /// Get the value for a field in an entry.
    pub fn get_field_value(
        &self,
        entry: &TableEntryType<E>,
        field: &FieldDescriptor,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        let (type_id, index) = { (field.type_id, field.index) };

        entry.get(index, type_id, out)
    }

    /// Execute a closure on all entries in the table with read-only access.
    ///
    /// The iteration continues until all entries are visited or the closure returns false.
    // TODO(upstream) the closure cannot store away the entry but we could use explicit docs
    pub fn iterate_entries<F>(&mut self, mut func: F) -> bool
    where
        F: FnMut(&mut TableEntryType<E>) -> bool,
    {
        for value in &mut self.data.write().values_mut() {
            if !func(&mut value.write_arc()) {
                return false;
            }
        }
        true
    }

    /// Remove all entries from the table.
    pub fn clear(&mut self) {
        self.data.write().clear()
    }

    /// Erase an entry by key.
    pub fn erase<Q>(&mut self, key: &Q) -> Option<TableEntryType<E>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        Some(self.data.write().remove(key)?.write_arc())
    }

    /// Create a new table entry.
    ///
    /// This is a detached entry that can be later inserted into the table using [`Table::insert`].
    pub fn create_entry(&self) -> Result<TableEntryType<E>, anyhow::Error> {
        Ok(new_shared_ref(ExtensibleEntry::new_with_metadata(
            self.name,
            &self.metadata,
        )?)
        .write_arc())
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
        let name = self.name;
        let metadata = self.metadata.clone();

        move || {
            Ok(new_shared_ref(ExtensibleEntry::new_with_metadata(
                name, &metadata,
            )?))
        }
    }

    /// Attach an entry to a table key
    pub fn insert<Q>(&mut self, key: &Q, entry: TableEntryType<E>) -> Option<TableEntryType<E>>
    where
        K: Borrow<Q>,
        Q: Ord + ToOwned<Owned = K> + ?Sized,
    {
        // note: different semantics from data.insert: we return the *new* entry
        let new_entry = std::sync::Arc::clone(RefGuard::rwlock(&entry));

        self.data
            .write()
            .insert(key.to_owned(), std::sync::Arc::clone(&new_entry));
        drop(entry);
        Some(new_entry.write_arc())
    }

    /// Write a value to a field of an entry
    pub fn write(
        &self,
        entry: &mut TableEntryType<E>,
        field: &FieldDescriptor,
        value: &ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        if field.read_only {
            return Err(anyhow::anyhow!("Field is read-only").context(FailureReason::NotSupported));
        }

        let (type_id, index) = { (field.type_id, field.index) };

        let value = unsafe {
            DynamicFieldValue::from_data(value, type_id).ok_or_else(|| {
                anyhow::anyhow!("Cannot store {:?} data (unsupported type)", type_id)
            })?
        };

        entry.set(index, value)
    }

    /// Return a list of fields as a slice of raw FFI objects
    pub fn list_fields(&mut self) -> &[ss_plugin_table_fieldinfo] {
        self.field_descriptors.clear();
        self.field_descriptors.extend(self.metadata.list_fields());
        self.field_descriptors.as_slice()
    }

    /// Return a field descriptor for a particular field
    ///
    /// The requested `field_type` must match the actual type of the field
    pub fn get_field(&self, name: &CStr, field_type: FieldTypeId) -> Option<FieldRef> {
        self.metadata
            .get_field(name)
            .filter(|f| f.as_ref().type_id == field_type)
    }

    /// Add a new field to the table
    pub fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<FieldRef> {
        self.metadata.add_field(name, field_type, read_only)
    }
}

#[cfg(test)]
mod tests {
    use crate::plugin::exported_tables::entry::dynamic::DynamicEntry;
    use crate::tables::export::Table;
    use crate::tables::import::Bool;
    use crate::tables::TablesInput;
    use std::ffi::CString;

    // Just a compile test
    #[allow(unused)]
    fn add_table(input: &TablesInput) -> anyhow::Result<()> {
        input.add_table(Table::<i8, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<i16, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<i32, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<i64, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<u8, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<u16, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<u32, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<u64, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<Bool, DynamicEntry>::new(c"exported")?)?;
        input.add_table(Table::<CString, DynamicEntry>::new(c"exported")?)?;

        Ok(())
    }
}
