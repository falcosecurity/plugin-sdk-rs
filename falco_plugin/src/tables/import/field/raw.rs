use crate::tables::data::Value;
use falco_plugin_api::ss_plugin_table_field_t;

#[derive(Debug)]
pub struct RawField<V: Value + ?Sized> {
    pub(crate) field: *mut ss_plugin_table_field_t,
    pub(crate) assoc_data: V::AssocData,
}
