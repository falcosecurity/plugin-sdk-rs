#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![deny(rustdoc::broken_intra_doc_links)]

// reexport dependencies
pub use anyhow;
pub use falco_plugin_api as api;
pub use phf;
pub use schemars;
pub use serde;

pub use crate::plugin::error::FailureReason;

pub mod async_event;
pub mod base;
pub mod event;
pub mod extract;
pub mod listen;
pub mod parse;
mod plugin;
pub mod source;
pub mod strings;
pub mod tables;

#[doc(hidden)]
pub mod internals {
    pub mod tables {
        crate::table_import_expose_internals!();
        crate::table_export_expose_internals!();
    }
}
