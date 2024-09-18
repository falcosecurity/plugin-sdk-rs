use crate::plugin::exported_tables::metadata::HasMetadata;
use anyhow::Error;
use std::ffi::CStr;
use std::ops::{Deref, DerefMut};

/// Do not export the field via Falco tables API
///
/// This is a wrapper that tells the Rust SDK not to export a field to other plugins.
/// It can be used to hold private plugin data or hold types that aren't supported
/// by the API (collections, enums etc.)
///
/// This type implements [`Deref`] and [`DerefMut`], so you do not need any extra
/// code when accessing the actual data.
///
/// **Note**: the wrapped type must implement [`Default`] as entries may be created
/// over the plugin API without any interaction with your plugin code.
#[derive(Debug)]
pub struct Private<T>(T);

impl<T> Deref for Private<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Private<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Default> HasMetadata for Private<T> {
    type Metadata = ();

    fn new_with_metadata(_tag: &'static CStr, _meta: &Self::Metadata) -> Result<Self, Error> {
        Ok(Self(T::default()))
    }
}
