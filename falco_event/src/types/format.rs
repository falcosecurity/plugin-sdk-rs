use std::fmt::Formatter;

/// Get a Falco-style string representation of a field or an event
///
/// The type parameter will generally be one of the structs from [`format_type`]
pub trait Format<F> {
    /// build a string representation according to the chosen formatting type
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result;
}

impl<T, F> Format<F> for Option<T>
where
    T: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        match self {
            Some(inner) => inner.format(fmt),
            None => fmt.write_str("NULL"),
        }
    }
}

#[allow(non_camel_case_types)]
/// Formatting types for the [`Format`] trait
///
/// These types are only used as tags to indicate to the [`Format`] trait what type of output
/// you're interested in.
///
/// **Note**: these are only supported for individual field types. Event types only support
/// the [`format_type::PF_NA`] format.
pub mod format_type {
    /// The default representation
    ///
    /// It's supported by all types and tries to come up with a sensible output
    /// for all types
    pub struct PF_NA;

    /// Decimal representation
    ///
    /// Available for integer types, newtypes over integers and `PT_BYTEBUF`s
    pub struct PF_DEC;

    /// Hexadecimal representation
    ///
    /// Available for integer types, newtypes over integers and `PT_BYTEBUF`s
    pub struct PF_HEX;

    /// Decimal padded to 10 decimal places
    ///
    /// Upstream libs use this to format relative timestamps with nanosecond resolution.
    /// Since we use the standard duration format, this tag is unused in this SDK.
    pub struct PF_10_PADDED_DEC;

    /// ID
    ///
    /// Upstream libs use this to format CPU and other ids. Since they're formatted as decimal
    /// numbers anyway, this tag is unused in this SDK.
    pub struct PF_ID;

    /// Event direction
    ///
    /// Upstream libs use this to format event direction (`>` or `<`). We have explicit support
    /// for formatting the direction, and so do not use this tag in the SDK.
    pub struct PF_DIR;

    /// Octal representation
    ///
    /// Available for integer types, newtypes over integers and `PT_BYTEBUF`s
    pub struct PF_OCT;
}
