use crate::plugin::exported_tables::field_value::dynamic::DynamicFieldValue;
use crate::plugin::exported_tables::field_value::traits::StaticField;
use crate::plugin::tables::data::FieldTypeId;
use falco_plugin_api::ss_plugin_state_data;
use std::marker::PhantomData;

/// A compile-time check for types implementing StaticField, providing associated constants
///
/// See <https://github.com/nvzqz/impls?tab=readme-ov-file#how-it-works> for how it works
pub trait StaticFieldFallback {
    /// for types not implementing StaticField, there's no type id
    const MAYBE_TYPE_ID: Option<FieldTypeId> = None;

    /// this is irrelevant for types not implementing StaticField, but it must exist
    const READONLY: bool = false;
}

impl<T> StaticFieldFallback for T {}

#[allow(missing_docs)]
#[allow(missing_debug_implementations)]
pub struct StaticFieldCheck<T>(PhantomData<T>);

impl<T> StaticFieldCheck<T>
where
    T: StaticField + TryFrom<DynamicFieldValue, Error = anyhow::Error>,
{
    /// get the type id from the actual StaticField implementation
    pub const MAYBE_TYPE_ID: Option<FieldTypeId> = Some(T::TYPE_ID);

    /// get the readonly flag from the actual StaticField implementation
    pub const READONLY: bool = T::READONLY;
}

/// A compile-time check for types implementing StaticField, providing a getter
///
/// See <https://github.com/nvzqz/impls?tab=readme-ov-file#how-it-works> for how it works
pub trait StaticFieldGetFallback {
    /// get a static field value (dummy implementation)
    fn static_field_get(
        &self,
        _type_id: FieldTypeId,
        _out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        anyhow::bail!("This isn't even an accessible field, how did you end up here?")
    }
}

impl<T> StaticFieldGetFallback for T {}

#[allow(missing_docs)]
#[allow(missing_debug_implementations)]
pub struct StaticFieldGet<'a, T>(pub &'a T);

impl<T> StaticFieldGet<'_, T>
where
    T: StaticField + TryFrom<DynamicFieldValue, Error = anyhow::Error>,
{
    /// get a static field value
    pub fn static_field_get(
        &self,
        type_id: FieldTypeId,
        out: &mut ss_plugin_state_data,
    ) -> Result<(), anyhow::Error> {
        self.0.to_data(out, type_id)
    }
}

/// A compile-time check for types implementing StaticField, providing a setter
///
/// See <https://github.com/nvzqz/impls?tab=readme-ov-file#how-it-works> for how it works
pub trait StaticFieldSetFallback {
    /// set a static field value (dummy implementation)
    fn static_field_set(&mut self, _value: DynamicFieldValue) -> Result<(), anyhow::Error> {
        anyhow::bail!("This isn't even an accessible field, how did you end up here?")
    }
}

impl<T> StaticFieldSetFallback for T {}

#[allow(missing_docs)]
#[allow(missing_debug_implementations)]
pub struct StaticFieldSet<'a, T>(pub &'a mut T);

impl<T> StaticFieldSet<'_, T>
where
    T: StaticField + TryFrom<DynamicFieldValue, Error = anyhow::Error>,
{
    /// get a static field value
    pub fn static_field_set(&mut self, value: DynamicFieldValue) -> Result<(), anyhow::Error> {
        *self.0 = value.try_into()?;
        Ok(())
    }
}
