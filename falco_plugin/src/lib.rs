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

pub use error::FailureReason;

pub mod async_event;
pub mod base;
mod error;
pub mod event;
pub mod extract;
pub mod listen;
pub mod parse;
pub mod source;
pub mod strings;
pub mod tables;
