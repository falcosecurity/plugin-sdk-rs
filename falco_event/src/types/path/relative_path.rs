use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::Borrow;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use typed_path::{UnixPath, UnixPathBuf};

/// A relative path
///
/// Events containing a parameter of this type will have an extra method available, derived
/// from the field name. For example, if the field is called `name`, the event type will have
/// a method called `name_dirfd` that returns the corresponding `dirfd` (as an `Option<PT_FD>`)
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RelativePath<'a>(
    #[cfg_attr(feature = "serde", serde(with = "crate::types::serde::unix_path"))] pub &'a UnixPath,
);

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

/// A relative path
///
/// Events containing a parameter of this type will have an extra method available, derived
/// from the field name. For example, if the field is called `name`, the event type will have
/// a method called `name_dirfd` that returns the corresponding `dirfd` (as an `Option<PT_FD>`)
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct OwnedRelativePath(
    #[cfg_attr(feature = "serde", serde(with = "crate::types::serde::unix_path"))] pub UnixPathBuf,
);

impl Borrow for OwnedRelativePath {
    type Borrowed<'b> = RelativePath<'b>;

    fn borrow(&self) -> Self::Borrowed<'_> {
        RelativePath(self.0.as_path())
    }
}

impl Debug for OwnedRelativePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "<...>{}", self.0.display())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::event_derive::{FromBytes, ToBytes};
    use crate::types::path::relative_path::RelativePath;

    #[cfg(feature = "serde")]
    use crate::types::OwnedRelativePath;
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

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_relative_path() {
        use typed_path::UnixPath;
        let path = RelativePath(UnixPath::new("/foo"));

        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(json, "\"/foo\"");

        let path2: OwnedRelativePath = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&path2).unwrap();
        assert_eq!(json, json2);
    }
}
