use crate::internals::tables::export::DynamicFieldValue;
use crate::plugin::exported_tables::field_value::traits::FieldValue;
use crate::plugin::exported_tables::field_value::traits::{seal, StaticField};
use crate::plugin::exported_tables::metadata::HasMetadata;
use crate::plugin::tables::data::FieldTypeId;
use anyhow::Error;
use falco_plugin_api::ss_plugin_state_data;
use std::ffi::CStr;
use std::ops::{Deref, DerefMut};

/// Export the field via Falco tables API with read-only access
///
/// This is a wrapper that tells the Rust SDK to export a field to other plugins,
/// but only with read access. Please note that this does not limit write access
/// from within your plugin (bypassing the table API).
///
/// This type implements [`Deref`] and [`DerefMut`], so you do not need any extra
/// code when accessing the actual data.
#[derive(Debug)]
pub struct Readonly<T>(T);

impl<T: FieldValue + Default> HasMetadata for Readonly<T> {
    type Metadata = ();

    fn new_with_metadata(_tag: &'static CStr, _meta: &Self::Metadata) -> Result<Self, Error> {
        Ok(Self(T::default()))
    }
}

impl<T> Deref for Readonly<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Readonly<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: FieldValue> seal::Sealed for Readonly<T> {}

impl<T: FieldValue> FieldValue for Readonly<T> {
    fn to_data(&self, out: &mut ss_plugin_state_data, type_id: FieldTypeId) -> Result<(), Error> {
        self.0.to_data(out, type_id)
    }
}

impl<T: StaticField> StaticField for Readonly<T> {
    const TYPE_ID: FieldTypeId = T::TYPE_ID;
    const READONLY: bool = true;
}

impl<T: TryFrom<DynamicFieldValue>> TryFrom<DynamicFieldValue> for Readonly<T> {
    type Error = T::Error;

    fn try_from(value: DynamicFieldValue) -> Result<Self, Self::Error> {
        Ok(Self(T::try_from(value)?))
    }
}
