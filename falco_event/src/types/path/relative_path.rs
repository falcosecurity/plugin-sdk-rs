use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use typed_path::UnixPath;

/// A relative path
///
/// Events containing a parameter of this type will have an extra method available, derived
/// from the field name. For example, if the field is called `name`, the event type will have
/// a method called `name_dirfd` that returns the corresponding `dirfd` (as an `Option<PT_FD>`)
pub struct RelativePath<'a>(pub &'a UnixPath);

impl<'a> ToBytes for RelativePath<'a> {
    fn binary_size(&self) -> usize {
        self.0.binary_size()
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        <&'a UnixPath>::default_repr()
    }
}

impl<'a> FromBytes<'a> for RelativePath<'a> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
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

    use crate::event_derive::{FromBytes, ToBytes};
    use crate::types::path::relative_path::RelativePath;

    use typed_path::UnixPathBuf;

    #[test]
    fn test_relative_path() {
        let path = UnixPathBuf::from_str("/foo").unwrap();
        let rel_path = RelativePath(path.as_path());
        let mut binary = Vec::new();

        rel_path.write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "/foo\0".as_bytes());

        let mut buf = binary.as_slice();
        let path = RelativePath::from_bytes(&mut buf).unwrap();
        assert_eq!(path.0.to_str().unwrap(), "/foo");
    }
}
