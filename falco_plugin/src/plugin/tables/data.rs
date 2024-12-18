use crate::plugin::tables::table::raw::RawTable;
use crate::tables::TablesInput;
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_field_type_FTYPE_UINT64, ss_plugin_state_data,
    ss_plugin_state_type_SS_PLUGIN_ST_BOOL, ss_plugin_state_type_SS_PLUGIN_ST_INT16,
    ss_plugin_state_type_SS_PLUGIN_ST_INT32, ss_plugin_state_type_SS_PLUGIN_ST_INT64,
    ss_plugin_state_type_SS_PLUGIN_ST_INT8, ss_plugin_state_type_SS_PLUGIN_ST_STRING,
    ss_plugin_state_type_SS_PLUGIN_ST_TABLE, ss_plugin_state_type_SS_PLUGIN_ST_UINT16,
    ss_plugin_state_type_SS_PLUGIN_ST_UINT32, ss_plugin_state_type_SS_PLUGIN_ST_UINT8,
    ss_plugin_table_field_t,
};
use num_derive::FromPrimitive;
use std::borrow::Borrow;
use std::ffi::{CStr, CString};
use std::fmt::{Debug, Formatter};

pub(in crate::plugin::tables) mod seal {
    pub trait Sealed {}
}

/// Types usable as table keys and values
#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum FieldTypeId {
    /// 8-bit signed int
    I8 = ss_plugin_state_type_SS_PLUGIN_ST_INT8,
    /// 16-bit signed int
    I16 = ss_plugin_state_type_SS_PLUGIN_ST_INT16,
    /// 32-bit signed int
    I32 = ss_plugin_state_type_SS_PLUGIN_ST_INT32,
    /// 64-bit signed int
    I64 = ss_plugin_state_type_SS_PLUGIN_ST_INT64,
    /// 8-bit unsigned int
    U8 = ss_plugin_state_type_SS_PLUGIN_ST_UINT8,
    /// 16-bit unsigned int
    U16 = ss_plugin_state_type_SS_PLUGIN_ST_UINT16,
    /// 32-bit unsigned int
    U32 = ss_plugin_state_type_SS_PLUGIN_ST_UINT32,
    /// 64-bit unsigned int
    U64 = ss_plugin_field_type_FTYPE_UINT64,
    /// A printable buffer of bytes, NULL terminated
    String = ss_plugin_state_type_SS_PLUGIN_ST_STRING,
    /// A table
    Table = ss_plugin_state_type_SS_PLUGIN_ST_TABLE,
    /// A boolean value, 4 bytes.
    Bool = ss_plugin_state_type_SS_PLUGIN_ST_BOOL,
}

/// # A trait describing types usable as table keys and values
pub trait TableData: seal::Sealed {
    /// The Falco plugin type id of the data
    const TYPE_ID: FieldTypeId;

    /// # Convert to the raw FFI representation
    ///
    /// **Note**: even though the signature specifies an owned value, this value technically
    /// still borrows from `self`, as it contains raw pointers (for string values)
    fn to_data(&self) -> ss_plugin_state_data;
}

/// # A trait describing types usable as table keys
pub trait Key: TableData {
    /// The type borrowed from the FFI representation
    type Borrowed: ?Sized;

    /// # Borrow from the raw FFI representation
    ///
    /// **Note**: this function only borrows the data and must return a reference.
    /// This means that Self::Borrowed must be repr(C) and compatible
    /// with the layout of `ss_plugin_state_data`, or otherwise constructible
    /// as a reference from a pointer to the actual data (e.g. CStr from a *const c_char).
    ///
    /// # Safety
    /// `data` must contain valid data of the correct type
    unsafe fn from_data(data: &ss_plugin_state_data) -> &Self::Borrowed
    where
        Self: Borrow<Self::Borrowed>;
}

/// # A trait describing types usable as table values
pub trait Value: TableData {
    /// The type of metadata attached to each field of this type
    ///
    /// Usually `()`, except for table-valued fields
    type AssocData;

    /// The type actually retrieved as the field value
    type Value<'a>
    where
        Self: 'a;

    /// Hydrate a [`ss_plugin_state_data`] value into the Rust representation
    ///
    /// # Safety
    /// Returns a value with arbitrary lifetime (cannot really express "until the next
    /// call across the API boundary" in the type system) so don't go crazy with 'static
    unsafe fn from_data_with_assoc<'a>(
        data: &ss_plugin_state_data,
        assoc: &Self::AssocData,
    ) -> Self::Value<'a>;

    /// Given a raw table, fetch the field's metadata
    ///
    /// The only interesting implementation is for `Box<Table>`, which gets all the fields
    /// of a nested table and stores it in the subtable metadata. All others are no-ops.
    ///
    /// # Safety
    /// Dereferences a raw pointer
    unsafe fn get_assoc_from_raw_table(
        table: &RawTable,
        field: *mut ss_plugin_table_field_t,
        tables_input: &TablesInput,
    ) -> Result<Self::AssocData, anyhow::Error>;
}

macro_rules! impl_table_data_direct {
    ($ty:ty => $field:ident: $type_id:expr) => {
        impl seal::Sealed for $ty {}
        impl TableData for $ty {
            const TYPE_ID: FieldTypeId = $type_id;

            fn to_data(&self) -> ss_plugin_state_data {
                ss_plugin_state_data { $field: *self }
            }
        }

        impl Key for $ty {
            type Borrowed = $ty;

            unsafe fn from_data(data: &ss_plugin_state_data) -> &Self {
                unsafe { &data.$field }
            }
        }

        impl Value for $ty {
            type AssocData = ();
            type Value<'a> = $ty;

            unsafe fn from_data_with_assoc<'a>(
                data: &ss_plugin_state_data,
                _assoc: &Self::AssocData,
            ) -> Self::Value<'a> {
                unsafe { data.$field }
            }

            unsafe fn get_assoc_from_raw_table(
                _table: &RawTable,
                _field: *mut ss_plugin_table_field_t,
                _tables_input: &TablesInput,
            ) -> Result<Self::AssocData, anyhow::Error> {
                Ok(())
            }
        }
    };
}

impl_table_data_direct!(u8 => u8_: FieldTypeId::U8);
impl_table_data_direct!(i8 => s8: FieldTypeId::I8);
impl_table_data_direct!(u16 => u16_: FieldTypeId::U16);
impl_table_data_direct!(i16 => s16: FieldTypeId::I16);
impl_table_data_direct!(u32 => u32_: FieldTypeId::U32);
impl_table_data_direct!(i32 => s32: FieldTypeId::I32);
impl_table_data_direct!(u64 => u64_: FieldTypeId::U64);
impl_table_data_direct!(i64 => s64: FieldTypeId::I64);

/// # A boolean value to use in tables
///
/// The boolean type in the plugin API is defined as a 32-bit value, which does not
/// necessarily correspond to the Rust [`bool`] type. Since we borrow the actual
/// value, we cannot convert it on the fly to the native Rust type.
///
/// This type serves as a wrapper, exposing conversion methods to/from Rust bool.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Bool(pub(crate) ss_plugin_bool);

impl Debug for Bool {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bool").field(&bool::from(*self)).finish()
    }
}

impl From<bool> for Bool {
    fn from(value: bool) -> Self {
        Self(value as ss_plugin_bool)
    }
}

impl From<Bool> for bool {
    fn from(value: Bool) -> Self {
        value.0 != 0
    }
}

impl seal::Sealed for Bool {}

impl TableData for Bool {
    const TYPE_ID: FieldTypeId = FieldTypeId::Bool;
    fn to_data(&self) -> ss_plugin_state_data {
        ss_plugin_state_data { b: self.0 }
    }
}

impl Value for Bool {
    type AssocData = ();
    type Value<'a> = bool;

    unsafe fn from_data_with_assoc<'a>(
        data: &ss_plugin_state_data,
        _assoc: &Self::AssocData,
    ) -> Self::Value<'a> {
        unsafe { data.b != 0 }
    }

    unsafe fn get_assoc_from_raw_table(
        _table: &RawTable,
        _field: *mut ss_plugin_table_field_t,
        _tables_input: &TablesInput,
    ) -> Result<Self::AssocData, anyhow::Error> {
        Ok(())
    }
}

impl Key for Bool {
    type Borrowed = Bool;

    unsafe fn from_data(data: &ss_plugin_state_data) -> &Self {
        unsafe { std::mem::transmute(&data.b) }
    }
}

impl seal::Sealed for CString {}

impl TableData for CString {
    const TYPE_ID: FieldTypeId = FieldTypeId::String;

    fn to_data(&self) -> ss_plugin_state_data {
        ss_plugin_state_data {
            str_: self.as_ptr(),
        }
    }
}

impl Key for CString {
    type Borrowed = CStr;

    unsafe fn from_data(data: &ss_plugin_state_data) -> &CStr {
        unsafe { CStr::from_ptr(data.str_) }
    }
}

impl seal::Sealed for CStr {}

impl TableData for CStr {
    const TYPE_ID: FieldTypeId = FieldTypeId::String;

    fn to_data(&self) -> ss_plugin_state_data {
        ss_plugin_state_data {
            str_: self.as_ptr(),
        }
    }
}

impl Value for CStr {
    type AssocData = ();
    type Value<'a> = &'a CStr;

    unsafe fn from_data_with_assoc<'a>(
        data: &ss_plugin_state_data,
        _assoc: &Self::AssocData,
    ) -> Self::Value<'a> {
        unsafe { CStr::from_ptr(data.str_) }
    }

    unsafe fn get_assoc_from_raw_table(
        _table: &RawTable,
        _field: *mut ss_plugin_table_field_t,
        _tables_input: &TablesInput,
    ) -> Result<Self::AssocData, anyhow::Error> {
        Ok(())
    }
}
