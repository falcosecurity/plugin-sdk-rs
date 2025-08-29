use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use typed_path::UnixPath;

/// A relative path
///
/// Events containing a parameter of this type will have an extra method available, derived
/// from the field name. For example, if the field is called `name`, the event type will have
/// a method called `name_dirfd` that returns the corresponding `dirfd` (as an `Option<PT_FD>`)
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RelativePath<'a>(pub &'a UnixPath);

impl<'a> ToBytes for RelativePath<'a> {
    #[inline]
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    #[inline]
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    #[inline]
    fn default_repr() -> impl ToBytes {
        <&'a UnixPath>::default_repr()
    }
}

impl<'a> FromBytes<'a> for RelativePath<'a> {
    #[inline]
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        Ok(Self(<&'a UnixPath>::from_bytes(buf)?))
    }
}

impl Debug for RelativePath<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "<...>{}", self.0.display())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::RelativePath;
    use crate::fields::{FromBytes, ToBytes};

    use typed_path::UnixPathBuf;

    #[test]
    fn test_relative_path() {
        let path = UnixPathBuf::from_str("/foo").unwrap();
        let rel_path = RelativePath(path.as_path());
        let mut binary = Vec::new();

        rel_path.write(&mut binary).unwrap();
        println!("{binary:02x?}");

        assert_eq!(binary.as_slice(), "/foo\0".as_bytes());

        let mut buf = binary.as_slice();
        let path = RelativePath::from_bytes(&mut buf).unwrap();
        assert_eq!(path.0.to_str().unwrap(), "/foo");
    }
}
