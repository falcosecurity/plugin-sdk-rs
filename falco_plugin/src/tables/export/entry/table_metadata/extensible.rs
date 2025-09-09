use crate::tables::export::entry::table_metadata::dynamic::DynamicFieldsOnly;
use crate::tables::export::entry::table_metadata::traits::TableMetadata;
use crate::tables::export::field_descriptor::FieldRef;
use crate::tables::export::metadata::Metadata;
use crate::tables::FieldTypeId;
use anyhow::Error;
use falco_plugin_api::ss_plugin_table_fieldinfo;
use std::ffi::CStr;

#[derive(Debug)]
pub struct ExtensibleEntryMetadata<M> {
    pub(crate) inner: M,
    custom_fields: DynamicFieldsOnly,
}

impl<M> Metadata for ExtensibleEntryMetadata<M>
where
    M: Metadata,
{
    fn new() -> Result<Self, Error> {
        Ok(Self {
            inner: M::new()?,
            custom_fields: DynamicFieldsOnly::new()?,
        })
    }
}

impl<M: TableMetadata> TableMetadata for ExtensibleEntryMetadata<M> {
    fn get_field(&self, name: &CStr) -> Option<FieldRef> {
        self.inner
            .get_field(name)
            .or_else(|| self.custom_fields.get_field(name))
    }

    fn add_field(
        &mut self,
        name: &CStr,
        field_type: FieldTypeId,
        read_only: bool,
    ) -> Option<FieldRef> {
        self.custom_fields.add_field(name, field_type, read_only)
    }

    fn list_fields(&self) -> Vec<ss_plugin_table_fieldinfo> {
        let mut fields = self.inner.list_fields();
        fields.extend(self.custom_fields.list_fields());
        fields
    }
}
