use crate::tables::FieldTypeId;
use falco_plugin_api::{ss_plugin_field_type, ss_plugin_table_fieldinfo};
use std::sync::Arc;

/// An opaque id describing a particular field
///
/// It's effectively an index describing the order in which the fields were added,
/// separately for static and dynamic fields
#[derive(Clone, Copy, Eq, PartialEq, Debug, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum FieldId {
    Static(usize),
    Dynamic(usize),
}

/// A reference to a field descriptor
///
/// For static fields, it's a static reference to the descriptor (stored in a static global
/// somewhere). For dynamic fields, it's a reference-counted pointer to the descriptor living
/// in a runtime-managed map
#[allow(missing_docs)]
#[derive(Debug)]
pub enum FieldRef {
    Static(&'static FieldDescriptor),
    Dynamic(Arc<FieldDescriptor>),
}

impl AsRef<FieldDescriptor> for FieldRef {
    fn as_ref(&self) -> &FieldDescriptor {
        match self {
            FieldRef::Static(s) => s,
            FieldRef::Dynamic(d) => d.as_ref(),
        }
    }
}

/// # A descriptor for a dynamically added field
///
/// It knows its sequential ID (to look up fields by numbers, not by strings all the time)
/// and the type of stored data.
///
/// **Note**: the data is stored as an enum capable of holding values of any type, but the table enforces
/// the defined type on all incoming data.
#[derive(Debug)]
pub struct FieldDescriptor {
    pub(crate) index: FieldId,
    pub(crate) type_id: FieldTypeId,
    pub(crate) read_only: bool,
}

impl FieldDescriptor {
    /// Create a field if needed
    ///
    /// This gets called by the derive macro for all entry fields, including private ones
    /// and returns a field descriptor only for fields that do need to be exposed over the API
    pub const fn maybe_new(
        index: FieldId,
        type_id: Option<FieldTypeId>,
        read_only: bool,
    ) -> Option<Self> {
        match type_id {
            Some(type_id) => Some(Self {
                index,
                type_id,
                read_only,
            }),
            None => None,
        }
    }

    /// Get the raw API representation of a field descriptor
    ///
    /// This is used to list table fields
    pub fn to_raw(&self, name: &'static [u8]) -> ss_plugin_table_fieldinfo {
        ss_plugin_table_fieldinfo {
            name: name.as_ptr().cast(),
            field_type: self.type_id as ss_plugin_field_type,
            read_only: self.read_only.into(),
        }
    }
}
