//! # Creating and accessing tables
//!
//! Tables are a mechanism to share data between plugins (and Falco core). There are three major
//! concepts that relate to working with Falco plugin tables:
//! - a table is a collection of entries, each under a different key, like a hash map or a SQL
//!   table with a single primary key
//! - an entry is a struct containing the actual values (corresponding to an entry in the hash map
//!   or a row in the SQL table)
//! - a field is a descriptor for a particular item in an entry. It does not have an equivalent
//!   in the hash map analogy, but corresponds to a column in the SQL table. In particular, a field
//!   is not attached to any particular entry.
//!
//! ## Example (in pseudocode)
//!
//! Consider a table called `threads` that has two fields:
//! ```ignore
//! struct Thread {
//!     uid: u64,
//!     comm: CString,
//! }
//! ```
//!
//! and uses the thread id (`tid: u64`) as the key. To read the `comm` of the thread with tid 1,
//! you would need the following operations:
//!
//! ```ignore
//! // get the table (at initialization time)
//! let threads_table = get_table("threads");
//!
//! // get the field (at initialization time)
//! let comm_field = threads_table.get_field("comm");
//!
//! // get an entry in the table (during parsing or extraction)
//! let tid1_entry = threads_table.get_entry(1);
//!
//! // get the field value from an entry
//! let comm = tid1_entry.get_field_value(comm_field);
//! ```
//!
//! The Rust SDK tries to hide this and expose a more struct-oriented approach, though you can
//! access fields in entries manually if you want (e.g. if you only know the field name at runtime).
//!
//! # Supported field types
//!
//! The following types can be used in fields visible over the plugin API:
//! - integer types (u8/i8, u16/i16, u32/i32, u64/i64)
//! - the bool type
//! - CString
//!
//! Any other types are not supported, including in particular e.g. collections (`Vec<T>`),
//! enums or any structs.
//!
//! # Nested tables
//!
//! Fields can also have a table type. This amounts to nested tables, like:
//! ```ignore
//! let fd_type = threads[tid].file_descriptors[fd].fd_type;
//! ```
//!
//! One important limitation is that you cannot add a nested table at runtime, so the only
//! nested tables that exist are defined by the plugin (or Falco core) which owns the parent table.
//!
//! # Exporting and importing tables
//!
//! Tables can be exported (exposed to other plugins) using the [`export`] module.
//!
//! Existing tables (from other plugins) can be imported using the [`import`] module.
//!
//! See the corresponding modules' documentation for details.
//!
//! # Access control
//!
//! Not all plugins are created equal when it comes to accessing tables. Only
//! [parse plugins](`crate::parse::ParsePlugin`), [listen plugins](`crate::listen::CaptureListenPlugin`)
//! and [extract plugins](`crate::extract::ExtractPlugin`) can access tables. Moreover, during field
//! extraction you can only read tables, not write them.
//!
//! To summarize:
//!
//! | Plugin type | Initialization phase | Action phase ^1 |
//! |-------------|----------------------|-----------------|
//! | source      | no access            | no access       |
//! | parse       | full access          | read/write      |
//! | extract     | full access ^2       | read only       |
//! | listen      | full access          | n/a ^3          |
//! | async       | no access            | no access       |
//!
//! **Notes**:
//! 1. "Action phase" is anything that happens after [`crate::base::Plugin::new`] returns, i.e.
//!    event generation, parsing/extraction or any background activity (in async plugins).
//!
//! 2. Even though you can create tables and fields during initialization of an extract plugin,
//!    there's no way to modify them later (create table entries or write to fields), so it's
//!    more useful to constrain yourself to looking up existing tables/fields.
//!
//! 3. Listen plugins don't really have an action phase as they only expose methods to run
//!    on capture start/stop. The routines they spawn cannot access tables, since the table
//!    API is explicitly not thread safe (but with the `thread-safe-tables` feature you can
//!    safely access tables from Rust plugins across many threads).
//!
//! ## Access control implementation
//!
//! Access control is implemented by requiring a particular object to actually perform table
//! operations:
//! - [`TablesInput`] to manage (look up/create) tables and fields
//! - [`TableReader`] to look up table entries and get field values
//! - [`TableWriter`] to create entries and write field values
//!
//! These get passed to your plugin whenever a particular class of operations is allowed.
//! Note that [`crate::base::Plugin::new`] receives an `Option<&TablesInput>` and the option
//! is populated only for parsing and extraction plugins (source and async plugins receive `None`).
//!
//! # The flow of using tables
//!
//! The access controls described above push you into structuring your plugins in a specific way.
//! You cannot e.g. define tables in a source plugin, which is good, since that would break
//! when reading capture files (the source plugin is not involved in that case). To provide
//! a full-featured plugin that generates events, maintains some state and exposes it via
//! extracted fields, you need separate capabilities (that may live in a single plugin or be
//! spread across different ones):
//! - a source plugin *only* generates events
//! - a parse plugin creates the state tables and updates them during event parsing
//! - an extract plugin reads the tables and returns field values
//!
//! # Dynamic fields
//!
//! Tables can have fields added to them at runtime, from other plugins than the one that
//! created them (you can add dynamic fields to tables you created too, but that makes little sense).
//!
//! These fields behave just like fields defined statically in the table and can be used by plugins
//! loaded after the current one. This can be used to e.g. add some data to an existing table
//! in a parse plugin and expose it in an extract plugin.
//!
//! # Thread safety
//!
//! Tables in the Falco plugin API are explicitly *not* thread safe. However, when you enable
//! the `thread-safe-tables` feature, tables exported from your plugin become thread-safe, so you
//! can use them from your plugin (e.g. in a separate thread) concurrently to other plugins
//! (in the main thread).

pub(crate) use vtable::fields::TableFields;
pub(crate) use vtable::reader::private::TableReaderImpl;
pub use vtable::reader::LazyTableReader;
pub use vtable::reader::TableReader;
pub use vtable::reader::ValidatedTableReader;
pub(crate) use vtable::writer::private::TableWriterImpl;
pub use vtable::writer::LazyTableWriter;
pub use vtable::writer::TableWriter;
pub use vtable::writer::ValidatedTableWriter;
pub use vtable::TablesInput;

mod data;
pub mod export;
pub mod import;
mod vtable;

// for macro use only
#[doc(hidden)]
pub use crate::tables::data::{Key, Value};

// for macro and crate-local use only
#[doc(hidden)]
pub use crate::tables::data::FieldTypeId;
