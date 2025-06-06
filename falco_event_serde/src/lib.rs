//! # Serde support for Falco events
//!
//! This crate provides serialization and deserialization support for Falco events using Serde.
//! The serialized format is as follows (using JSON as an example):
//!
//! ```json
//! {
//!     "ts": 1700000000,     // timestamp in nanoseconds since epoch
//!     "tid": 12345,         // thread ID
//!     "GENERIC_E": {        // event type name (as enum variant name)
//!         "id": 1,          // event parameters
//!         "native_id": 1001
//!     }
//! }
//! ```
//!
//! The event names correspond to variants of [`falco_event::events::types::AnyEvent`] (i.e.,
//! with the `PPME_` prefix removed).
//!
//! ## Serialization rules for different parameter types
//!
//! * Integers (`PT_UINT*`, `PT_INT*`, etc.) and newtype wrappers (`PT_SYSCALLID` etc.) are
//!   serialized as numbers.
//!
//! * Bit flags (`PT_FLAGS*`) and enum flags (`PT_ENUMFLAGS*`) are serialized as numbers, using
//!   the underlying integer value.
//!
//! * Relative timestamps (`PT_RELTIME`) are serialized as the number of nanoseconds in the interval.
//!
//! * Absolute timestamps (`PT_ABSTIME`) are serialized as the number of nanoseconds since the epoch.
//!
//! * File descriptor lists (`PT_FDLIST`) are serialized as arrays of tuples containing two integers
//!   for the file descriptor (`u64`) and its associated flags (`PT_FLAGS16_file_flags`).
//!
//! * Strings, byte buffers and file paths (`PT_CHARBUF`, `PT_BYTES`, `PT_FSPATH`, `PT_FSRELPATH`)
//!   are serialized as strings if they contain valid UTF-8 and the serializer marks itself
//!   as human-readable (e.g., JSON), or as a byte array otherwise.
//!
//! * Strings inside arrays of strings (`PT_CHARBUFARRAY`) are serialized with the logic above.
//!
//! * Arrays of string pairs (`PT_CHARBUF_PAIR_ARRAY`) are serialized as arrays of tuples (*not*
//!   as maps) containing two strings, serialized using the same logic as all other strings.
//!
//! * Dynamic fields (`PT_DYN*`) are serialized as an enum (using the default externally tagged
//!   representation).
//!
//! *  Socket addresses (`PT_SOCKADDR`) are serialized in different formats, depending on the address
//!    family:
//!    * `AF_UNIX`: a string for the path
//!    * `AF_INET`, `AF_INET6`: a tuple of `ip` (as a string) and `port` (as a number)
//!    * other: a tuple of a single byte for the address family and a string (or byte array if not
//!      valid UTF-8) for the address
//!
//! * Socket tuples (`PT_SOCKTUPLE`) are serialized depending on the address family:
//!   * `AF_UNIX`: a tuple of two integers for the source and destination pointers and a string
//!     for the path
//!   * `AF_INET`, `AF_INET6`: a tuple of four items: source IP (as a string), source port
//!     (as a number), destination IP (as a string), and destination port (as a number)
//!   * other: like `PT_SOCKADDR`
#![warn(missing_docs)]
pub mod de;
pub mod ser;

#[doc(hidden)]
pub use falco_event::fields;

#[doc(hidden)]
pub use falco_event::ffi;
