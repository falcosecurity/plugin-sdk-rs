//! Exporting tables to other plugins
//!
//! Exporting a table to other plugins is done using the [`Entry`] derive macro.
//! It lets you use a struct type as a parameter to [`Table`]. You can then create
//! a new table using [`TablesInput::add_table`](crate::tables::TablesInput::add_table).
//!
//! Every field in the entry struct must be wrapped in [`Public`](`crate::tables::export::Public`),
//! [`Private`](`crate::tables::export::Private`) or [`Readonly`](`crate::tables::export::Readonly`),
//! except for nested tables. These just need to be a `Box<Table<K, E>>`, as it makes no sense
//! to have a private nested table and the distinction between writable and readonly is meaningless
//! for tables (they have no setter to replace the whole table and you can always add/remove
//! entries from the nested table).
//!
//! # Example
//!
//! ```
//! use std::ffi::{CStr, CString};
//! use falco_plugin::base::Plugin;
//!# use falco_plugin::plugin;
//! use falco_plugin::tables::TablesInput;
//! use falco_plugin::tables::export;
//!
//! // define the struct representing each table entry
//! #[derive(export::Entry)]
//! struct ExportedTable {
//!     int_field: export::Readonly<u64>,      // do not allow writes via the plugin API
//!     string_field: export::Public<CString>, // allow writes via the plugin API
//!     secret: export::Private<Vec<u8>>,      // do not expose over the plugin API at all
//! }
//!
//! // define the type holding the plugin state
//! struct MyPlugin {
//!     // you can use methods on this instance to access fields bypassing the Falco table API
//!     // (for performance within your own plugin)
//!     exported_table: Box<export::Table<u64, ExportedTable>>,
//! }
//!
//! // implement the base::Plugin trait
//! impl Plugin for MyPlugin {
//!     // ...
//!#     const NAME: &'static CStr = c"sample-plugin-rs";
//!#     const PLUGIN_VERSION: &'static CStr = c"0.0.1";
//!#     const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
//!#     const CONTACT: &'static CStr = c"you@example.com";
//!#     type ConfigType = ();
//!
//!     fn new(input: Option<&TablesInput>, config: Self::ConfigType)
//!         -> Result<Self, anyhow::Error> {
//!
//!         let Some(input) = input else {
//!             anyhow::bail!("Did not get tables input");
//!         };
//!
//!         // create a new table called "exported"
//!         //
//!         // The concrete type is inferred from the field type the result is stored in.
//!         let exported_table = input.add_table(export::Table::new(c"exported")?)?;
//!
//!         Ok(MyPlugin { exported_table })
//!     }
//! }
//!# plugin!(#[no_capabilities] MyPlugin);
//! ```

mod entry;
mod field;
mod field_descriptor;
mod field_value;
mod macros;
mod metadata;
pub(crate) mod ref_shared;
pub(crate) mod static_field_specialization;
pub(crate) mod table;
pub(crate) mod vtable;
pub(crate) mod wrappers;

pub use field::private::Private;
pub use field::public::Public;
pub use field::readonly::Readonly;
pub use table::Table;

// for macro and crate-local use only
#[doc(hidden)]
pub mod traits {
    pub use super::entry::table_metadata::traits::TableMetadata;
    pub use super::entry::traits::Entry;
}

// for macro use only
#[doc(hidden)]
pub use field_descriptor::{FieldDescriptor, FieldId, FieldRef};

// for macro use only
#[doc(hidden)]
pub use field_value::dynamic::DynamicFieldValue;

// for macro use only
#[doc(hidden)]
pub use metadata::{HasMetadata, Metadata};

/// Mark a struct type as a table value
///
/// See the [module documentation](`crate::tables::export`) for details.
pub use falco_plugin_derive::Entry;
