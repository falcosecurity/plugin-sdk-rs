use crate::event_derive::{FromBytes, FromBytesError, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::{Borrow, Borrowed};
use std::ffi::{CStr, CString};
use std::fmt::Formatter;
use std::io::Write;

impl<'a> FromBytes<'a> for &'a CStr {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
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

impl<F> Format<F> for &CStr
where
    for<'a> &'a [u8]: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let bytes = self.to_bytes();
        bytes.format(fmt)
    }
}

impl Borrowed for CStr {
    type Owned = CString;
}

impl Borrow for CString {
    type Borrowed<'a> = &'a CStr;

    fn borrow(&self) -> Self::Borrowed<'_> {
        self.as_c_str()
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    #[allow(dead_code)]
    pub mod cstr {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use std::ffi::{CStr, CString};

        pub fn serialize<S: Serializer>(buf: &CStr, ser: S) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks = UtfChunked::from(buf.to_bytes());
                chunks.serialize(ser)
            } else {
                buf.serialize(ser)
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<CString, D::Error> {
            let chunks: OwnedUtfChunked = Deserialize::deserialize(de)?;
            let s = CString::new(chunks.into_vec()).map_err(|e| D::Error::custom(e.to_string()))?;
            Ok(s)
        }
    }

    pub mod cstr_option {
        use crate::types::utf_chunked::UtfChunked;
        use serde::{Serialize, Serializer};
        use std::ffi::CStr;

        pub fn serialize<S: Serializer>(buf: &Option<&CStr>, ser: S) -> Result<S::Ok, S::Error> {
            let chunks = buf.map(|buf| UtfChunked::from(buf.to_bytes()));
            chunks.serialize(ser)
        }
    }

    pub mod cstr_option_owned {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use std::ffi::CString;

        pub fn serialize<S: Serializer>(buf: &Option<CString>, ser: S) -> Result<S::Ok, S::Error> {
            let chunks = buf.as_ref().map(|buf| UtfChunked::from(buf.to_bytes()));
            chunks.serialize(ser)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<CString>, D::Error> {
            let chunks: Option<OwnedUtfChunked> = Deserialize::deserialize(de)?;
            let s = chunks
                .map(|chunks| {
                    CString::new(chunks.into_vec()).map_err(|e| D::Error::custom(e.to_string()))
                })
                .transpose()?;
            Ok(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event_derive::{FromBytes, ToBytes};
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
