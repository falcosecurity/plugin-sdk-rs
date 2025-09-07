use crate::tables::export::entry::dynamic::DynamicEntry;
use crate::tables::export::entry::table_metadata::extensible::ExtensibleEntryMetadata;
use crate::tables::export::entry::traits::Entry;
use crate::tables::export::field_descriptor::FieldId;
use crate::tables::export::field_value::dynamic::DynamicFieldValue;
use crate::tables::export::metadata::HasMetadata;
use crate::tables::export::ref_shared::RefShared;
use crate::tables::import::data::FieldTypeId;
use anyhow::Error;
use falco_plugin_api::ss_plugin_state_data;
use std::ffi::CStr;
use std::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct ExtensibleEntry<E> {
    inner: E,
    custom_fields: DynamicEntry,
}

impl<E> Deref for ExtensibleEntry<E> {
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<E> DerefMut for ExtensibleEntry<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<E> HasMetadata for ExtensibleEntry<E>
where
    E: HasMetadata,
{
    type Metadata = RefShared<ExtensibleEntryMetadata<E::Metadata>>;

    fn new_with_metadata(tag: &'static CStr, meta: &Self::Metadata) -> Result<Self, Error> {
        Ok(Self {
            inner: E::new_with_metadata(tag, &meta.read_arc().inner)?,
            custom_fields: Default::default(),
        })
    }
}

impl<E> Entry for ExtensibleEntry<E>
where
    E: Entry,
{
    fn get(
        &self,
        key: FieldId,
        type_id: FieldTypeId,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), Error> {
        match key {
            FieldId::Static(_) => self.inner.get(key, type_id, out),
            FieldId::Dynamic(_) => Entry::get(&self.custom_fields, key, type_id, out),
        }
    }

    fn set(&mut self, key: FieldId, value: DynamicFieldValue) -> Result<(), Error> {
        match key {
            FieldId::Static(_) => self.inner.set(key, value),
            FieldId::Dynamic(_) => Entry::set(&mut self.custom_fields, key, value),
        }
    }
}
