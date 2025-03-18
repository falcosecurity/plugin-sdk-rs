use crate::types::Borrow;
use std::fmt::Formatter;

/// Get a Falco-style string representation of a field or an event
pub trait Format {
    /// build a string representation according to the chosen formatting type
    fn format(&self, format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result;
}

impl<T> Format for Option<T>
where
    T: Format,
{
    fn format(&self, format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        match self {
            Some(inner) => inner.format(format_type, fmt),
            None => fmt.write_str("NULL"),
        }
    }
}

impl<T> Format for T
where
    T: Borrow,
    for<'a> <T as Borrow>::Borrowed<'a>: Format,
{
    fn format(&self, format_type: FormatType, fmt: &mut Formatter) -> std::fmt::Result {
        self.borrow().format(format_type, fmt)
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
/// Formatting types for the [`Format`] trait
///
/// These variants are used as tags to indicate to the [`Format`] trait what type of output
/// you're interested in.
///
/// **Note**: these are only supported for individual field types. Event types only support
/// the [`FormatType::PF_NA`] format.
pub enum FormatType {
    /// The default representation
    ///
    /// It's supported by all types and tries to come up with a sensible output
    /// for all types
    PF_NA,

    /// Decimal representation
    ///
    /// Available for integer types, newtypes over integers and `PT_BYTEBUF`s
    PF_DEC,

    /// Hexadecimal representation
    ///
    /// Available for integer types, newtypes over integers and `PT_BYTEBUF`s
    PF_HEX,

    /// Decimal padded to 10 decimal places
    ///
    /// Upstream libs use this to format relative timestamps with nanosecond resolution.
    /// Since we use the standard duration format, this tag is unused in this SDK.
    PF_10_PADDED_DEC,

    /// ID
    ///
    /// Upstream libs use this to format CPU and other ids. Since they're formatted as decimal
    /// numbers anyway, this tag is unused in this SDK.
    PF_ID,

    /// Event direction
    ///
    /// Upstream libs use this to format event direction (`>` or `<`). We have explicit support
    /// for formatting the direction, and so do not use this tag in the SDK.
    PF_DIR,

    /// Octal representation
    ///
    /// Available for integer types, newtypes over integers and `PT_BYTEBUF`s
    PF_OCT,
}
