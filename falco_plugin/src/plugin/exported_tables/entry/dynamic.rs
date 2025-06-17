use crate::plugin::exported_tables::entry::table_metadata::dynamic::DynamicFieldsOnly;
use crate::plugin::exported_tables::entry::traits::Entry;
use crate::plugin::exported_tables::field_descriptor::FieldId;
use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::exported_tables::field_value::traits::FieldValue;
use crate::plugin::exported_tables::metadata::HasMetadata;
use crate::plugin::exported_tables::ref_shared::RefShared;
use crate::plugin::tables::data::FieldTypeId;
use falco_plugin_api::ss_plugin_state_data;
use std::ffi::CStr;

/// A table value type that only has dynamic fields
pub type DynamicEntry = Vec<DynamicFieldValue>;

impl HasMetadata for DynamicEntry {
    type Metadata = RefShared<DynamicFieldsOnly>;

    fn new_with_metadata(
        _tag: &'static CStr,
        _meta: &Self::Metadata,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self::default())
    }
}

impl Entry for DynamicEntry {
    fn get(
        &self,
        key: FieldId,
        type_id: FieldTypeId,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        match key {
            FieldId::Static(_) => Err(anyhow::anyhow!(
                "DynamicEntry does not support static fields"
            )),
            FieldId::Dynamic(id) => {
                let field = self
                    .as_slice()
                    .get(id)
                    .ok_or_else(|| anyhow::anyhow!("Dynamic field {:?} not found", key))?;

                field.to_data(out, type_id)
            }
        }
    }

    fn set(&mut self, key: FieldId, value: DynamicFieldValue) -> Result<(), anyhow::Error> {
        match key {
            FieldId::Static(_) => Err(anyhow::anyhow!(
                "DynamicEntry does not support static fields"
            )),
            FieldId::Dynamic(id) => {
                if id == self.len() {
                    self.push(value);
                } else if id < self.len() {
                    self[id] = value;
                } else {
                    self.resize_with(id, || DynamicFieldValue::None);
                    self.push(value);
                }
                Ok(())
            }
        }
    }
}
