use crate::fields::{FromBytes, FromBytesError, ToBytes};
use crate::types::ByteBufFormatter;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::io::Write;

impl<'a> FromBytes<'a> for &'a CStr {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        let cstr = CStr::from_bytes_until_nul(buf).map_err(|_| FromBytesError::MissingNul)?;
        let len = cstr.to_bytes().len();
        *buf = &buf[len + 1..];
        Ok(cstr)
    }
}

impl ToBytes for &CStr {
    fn binary_size(&self) -> usize {
        self.to_bytes().len() + 1
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.to_bytes_with_nul())
    }

    fn default_repr() -> impl ToBytes {
        0u8
    }
}

pub struct CStrFormatter<'a>(pub &'a CStr);

impl Debug for CStrFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&ByteBufFormatter(self.0.to_bytes()), f)
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{FromBytes, ToBytes};
    use std::ffi::CStr;

    #[test]
    fn test_cstr() {
        let s = CStr::from_bytes_until_nul(b"foo\0").unwrap();

        let mut binary = Vec::new();
        s.write(&mut binary).unwrap();

        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), b"foo\0".as_slice());

        let mut buf = binary.as_slice();
        let s2 = <&CStr>::from_bytes(&mut buf).unwrap();

        assert_eq!(s2.to_bytes_with_nul(), b"foo\0".as_slice());
        assert_eq!(buf.len(), 0);
    }
}
