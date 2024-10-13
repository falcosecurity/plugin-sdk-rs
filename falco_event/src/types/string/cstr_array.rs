use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::{Borrow, Borrowed};
use std::ffi::{CStr, CString};
use std::fmt::{Formatter, Write as _};
use std::io::Write;

impl<'a> ToBytes for Vec<&'a CStr> {
    fn binary_size(&self) -> usize {
        self.iter().map(|s| s.binary_size()).sum()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        for s in self {
            s.write(&mut writer)?;
        }

        Ok(())
    }

    fn default_repr() -> impl ToBytes {
        Self::new()
    }
}

impl<'a> FromBytes<'a> for Vec<&'a CStr> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let mut data = Vec::new();
        while !buf.is_empty() {
            data.push(FromBytes::from_bytes(buf)?);
        }
        Ok(data)
    }
}

impl<'a, F> Format<F> for Vec<&'a CStr>
where
    &'a CStr: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let mut is_first = true;
        for s in self {
            if is_first {
                is_first = false;
            } else {
                fmt.write_char(';')?;
            }

            s.format(fmt)?;
        }

        Ok(())
    }
}

impl<'a> Borrowed for Vec<&'a CStr> {
    type Owned = Vec<CString>;
}

impl Borrow for Vec<CString> {
    type Borrowed<'a> = Vec<&'a CStr>
    where
        Self: 'a;

    fn borrow(&self) -> Self::Borrowed<'_> {
        self.iter().map(|s| s.as_c_str()).collect()
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    #[allow(dead_code)]
    pub mod cstr_array {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use std::ffi::{CStr, CString};

        pub fn serialize<S: Serializer>(arr: &[&CStr], ser: S) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks: Vec<_> = arr
                    .iter()
                    .map(|buf| UtfChunked::from(buf.to_bytes()))
                    .collect();
                chunks.serialize(ser)
            } else {
                arr.serialize(ser)
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<CString>, D::Error> {
            let chunks: Vec<OwnedUtfChunked> = Deserialize::deserialize(de)?;
            let s: Result<Vec<CString>, D::Error> = chunks
                .into_iter()
                .map(|c| CString::new(c.into_vec()).map_err(|e| D::Error::custom(e.to_string())))
                .collect();
            s
        }
    }

    pub mod cstr_array_option {
        use crate::types::utf_chunked::UtfChunked;
        use serde::{Serialize, Serializer};
        use std::ffi::CStr;

        pub fn serialize<S: Serializer>(
            arr: &Option<Vec<&CStr>>,
            ser: S,
        ) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks: Option<Vec<_>> = arr.as_ref().map(|arr| {
                    arr.iter()
                        .map(|buf| UtfChunked::from(buf.to_bytes()))
                        .collect()
                });
                chunks.serialize(ser)
            } else {
                arr.serialize(ser)
            }
        }
    }

    pub mod cstr_array_option_owned {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use std::ffi::CString;

        pub fn serialize<S: Serializer>(
            arr: &Option<Vec<CString>>,
            ser: S,
        ) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks: Option<Vec<_>> = arr.as_ref().map(|arr| {
                    arr.iter()
                        .map(|buf| UtfChunked::from(buf.to_bytes()))
                        .collect()
                });
                chunks.serialize(ser)
            } else {
                arr.serialize(ser)
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            de: D,
        ) -> Result<Option<Vec<CString>>, D::Error> {
            let chunks: Option<Vec<OwnedUtfChunked>> = Deserialize::deserialize(de)?;
            let s: Result<Option<Vec<CString>>, D::Error> = chunks
                .map(|chunks| {
                    chunks
                        .into_iter()
                        .map(|c| {
                            CString::new(c.into_vec()).map_err(|e| D::Error::custom(e.to_string()))
                        })
                        .collect()
                })
                .transpose();
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event_derive::{FromBytes, ToBytes};
    use std::ffi::CStr;

    #[test]
    fn test_str_array() {
        let arr = vec![
            CStr::from_bytes_until_nul(b"foo\0").unwrap(),
            CStr::from_bytes_until_nul(b"bar\0").unwrap(),
        ];

        let mut binary = Vec::new();
        arr.write(&mut binary).unwrap();

        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), b"foo\0bar\0".as_slice());

        let mut buf = binary.as_slice();
        let loaded = <Vec<&CStr>>::from_bytes(&mut buf).unwrap();

        assert_eq!(arr, loaded)
    }

    #[test]
    fn test_str_empty_array() {
        let arr: Vec<&CStr> = Vec::new();

        let mut binary = Vec::new();
        arr.write(&mut binary).unwrap();

        hexdump::hexdump(binary.as_slice());

        assert!(binary.as_slice().is_empty());

        let mut buf = binary.as_slice();
        let loaded = <Vec<&CStr>>::from_bytes(&mut buf).unwrap();

        assert_eq!(arr, loaded)
    }

    #[test]
    fn test_str_array_with_empty_strings() {
        let mut buf = b"\0\0\0".as_slice();
        let loaded = <Vec<&CStr>>::from_bytes(&mut buf).unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(loaded.iter().all(|s| s.is_empty()))
    }
}
