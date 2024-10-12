use crate::types::Borrow;
use std::io::Write;

/// Convert a field to binary representation
pub trait ToBytes {
    /// Return the number of bytes needed to store the field
    fn binary_size(&self) -> usize;

    /// Write the binary representation to `writer`
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()>;

    /// Return the default representation for the field type
    ///
    /// **Note**: this does not need to be the same type as the implementing type.
    /// For example, an empty C-style string can be represented e.g. by returning `0u8`.
    fn default_repr() -> impl ToBytes;
}

/// A pseudo-field that cannot be written (returns an error at runtime)
///
/// This is useful for types that do not have a default representation (e.g. `PT_DYN` types)
///
/// **Note**: all event fields are generated as `Option<T>`, so there is always a possibility
/// that we get to write a default value for a field that does not have one.
pub struct NoDefault;

impl ToBytes for NoDefault {
    fn binary_size(&self) -> usize {
        0
    }

    fn write<W: Write>(&self, _writer: W) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "field cannot be empty when writing",
        ))
    }

    fn default_repr() -> impl ToBytes {
        Self
    }
}

impl<T: ToBytes> ToBytes for Option<T> {
    fn binary_size(&self) -> usize {
        if let Some(inner) = &self {
            inner.binary_size()
        } else {
            Self::default_repr().binary_size()
        }
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        match self {
            Some(ref val) => val.write(writer),
            None => T::default_repr().write(writer),
        }
    }

    fn default_repr() -> impl ToBytes {
        T::default_repr()
    }
}

impl<T> ToBytes for T
where
    T: Borrow + 'static,
    for<'a> <T as Borrow>::Borrowed<'a>: ToBytes,
{
    fn binary_size(&self) -> usize {
        self.borrow().binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.borrow().write(writer)
    }

    fn default_repr() -> impl ToBytes {
        <T as Borrow>::Borrowed::default_repr()
    }
}
