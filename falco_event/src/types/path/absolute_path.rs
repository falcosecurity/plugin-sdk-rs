use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::ffi::CStr;
use std::io::Write;
use typed_path::UnixPath;

impl<'a> FromBytes<'a> for &'a UnixPath {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        let buf = <&CStr>::from_bytes(buf)?;
        Ok(UnixPath::new(buf.to_bytes()))
    }
}

impl ToBytes for &UnixPath {
    fn binary_size(&self) -> usize {
        self.as_bytes().len() + 1
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.as_bytes().write(&mut writer)?;
        0u8.write(writer)
    }

    fn default_repr() -> impl ToBytes {
        0u8
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{FromBytes, ToBytes};
    use std::str::FromStr;
    use typed_path::{UnixPath, UnixPathBuf};

    #[test]
    fn test_absolute_path() {
        let path = UnixPathBuf::from_str("/foo").unwrap();
        let mut binary = Vec::new();

        assert_eq!(path.as_path().binary_size(), 5);

        path.as_path().write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "/foo\0".as_bytes());

        let mut buf = binary.as_slice();
        let path = <&UnixPath>::from_bytes(&mut buf).unwrap();
        assert_eq!(path.to_str().unwrap(), "/foo");
    }
}
