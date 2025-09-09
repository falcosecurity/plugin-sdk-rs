use crate::tables::FieldTypeId;
use falco_plugin_api::ss_plugin_state_data;

pub(crate) mod seal {
    pub trait Sealed {}
}

/// Trait implemented for types that can be table fields (both static and containers for dynamic fields)
///
/// This trait is sealed, meaning you cannot add new implementations (the list is limited
/// by the Falco plugin API)
pub trait FieldValue: seal::Sealed + Sized {
    /// Store a C representation of `&self` in `out`
    ///
    /// This method must return `Err` (and do nothing) if `&self` cannot be represented
    /// as a value of type [`FieldTypeId`].
    fn to_data(
        &self,
        out: &mut ss_plugin_state_data,
        type_id: FieldTypeId,
    ) -> Result<(), anyhow::Error>;
}

/// Trait implemented for types that can be static table fields
///
/// This trait is sealed, meaning you cannot add new implementations (the list is limited
/// by the Falco plugin API)
pub trait StaticField: FieldValue {
    /// The type id corresponding to the implementing type
    const TYPE_ID: FieldTypeId;

    const READONLY: bool;
}
