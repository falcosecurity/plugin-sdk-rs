mod bytebuf;
mod fd_list;
mod net;
mod owned;
mod path;
mod primitive;
mod string;
mod time;
#[cfg(feature = "serde")]
mod utf_chunked;

#[cfg(feature = "serde")]
pub mod serde {
    pub use super::bytebuf::serde::*;
    pub use super::string::serde::*;
}

/// Falco-style formatting for fields and events
///
/// This module provides the [`format::Format`] trait, which, similar to [`std::fmt::Debug`], enables
/// you to get a text representation of a field or an event. The differences compared to `Debug`
/// are:
/// - the output format follows the formatters from `libsinsp` (although it's not exact, as it uses
///   e.g. the `Debug` impl for [`std::time::Duration`] for pretty printing time intervals)
/// - the output can be configured in a limited fashion using [`format::FormatType`].
pub mod format;

pub use fd_list::*;
pub use net::*;
pub use owned::Borrow;
pub use owned::BorrowDeref;
pub use path::*;
pub use primitive::*;
