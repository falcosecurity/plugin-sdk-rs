#![doc = include_str!("../README.md")]

#[cfg(feature = "derive_deftly")]
pub use derive_deftly;
use std::ffi::CStr;

/// All the types available in event fields
pub mod fields;
mod types;

/// # Event types
///
/// This module is automatically generated from the Falco event schema. It provides strongly-typed
/// structs for each event type supported by Falco, as well as a [`events::AnyEvent`] enum that is capable
/// of containing an arbitrary event matching the schema.
#[allow(clippy::crate_in_macro_def)]
pub mod events;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(missing_docs)]
#[allow(unsafe_op_in_unsafe_fn)]
#[doc(hidden)]
pub mod ffi;

#[cfg(test)]
mod tests;

/// The schema version supported by this crate
///
/// If you're not using the same version of falco_event_schema and falco_plugin, you need
/// to expose this constant as `Plugin::SCHEMA_VERSION`.
pub const SCHEMA_VERSION: &CStr = {
    match CStr::from_bytes_with_nul(concat!(include_str!("../api/SCHEMA_VERSION"), "\0").as_bytes())
    {
        Ok(s) => s,
        Err(_) => panic!("Failed to parse SCHEMA_VERSION: embedded null byte in string"),
    }
};
