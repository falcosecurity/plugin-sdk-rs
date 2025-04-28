#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub use derive_deftly;
pub use num_traits;

#[allow(missing_docs)]
pub mod events;

/// All the types available in event fields
pub mod fields;
mod types;

pub use types::format;
pub use types::SystemTimeFormatter;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(missing_docs)]
#[allow(unsafe_op_in_unsafe_fn)]
#[doc(hidden)]
pub mod ffi;

// things for the derive macro to access under a well-known name
mod event_derive {
    pub use byteorder::NativeEndian;
    pub use byteorder::ReadBytesExt;
    pub use byteorder::WriteBytesExt;

    pub use crate::events::payload::PayloadFromBytesError;
    pub use crate::events::payload::PayloadFromBytesResult;
    pub use crate::events::Event;
    pub use crate::events::PayloadFromBytes;
    pub use crate::events::PayloadToBytes;
    pub use crate::events::RawEvent;
    pub use crate::fields::FromBytes;
    pub use crate::fields::FromBytesError;
    pub use crate::fields::FromBytesResult;
    pub use crate::fields::NoDefault;
    pub use crate::fields::ToBytes;
    pub use crate::types::format::OptionFormatter;
    pub use crate::types::ByteBufFormatter;
    pub use crate::types::CStrArrayFormatter;
    pub use crate::types::CStrFormatter;
    pub use crate::types::CStrPairArrayFormatter;
    pub use crate::types::SystemTimeFormatter;
}
