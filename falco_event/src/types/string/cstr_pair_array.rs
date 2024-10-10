use crate::event_derive::{FromBytes, FromBytesError, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::{Borrow, Borrowed};
use std::ffi::{CStr, CString};
use std::fmt::{Formatter, Write as _};
use std::io::Write;

impl<'a> ToBytes for Vec<(&'a CStr, &'a CStr)> {
    fn binary_size(&self) -> usize {
        self.iter()
            .map(|(s1, s2)| s1.binary_size() + s2.binary_size())
            .sum()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        for (s1, s2) in self {
            s1.write(&mut writer)?;
            s2.write(&mut writer)?;
        }

        Ok(())
    }

    fn default_repr() -> impl ToBytes {
        Self::new()
    }
}

impl<'a> FromBytes<'a> for Vec<(&'a CStr, &'a CStr)> {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
        let flat_data: Vec<&'a CStr> = FromBytes::from_bytes(buf)?;
        let mut chunks = flat_data.chunks_exact(2);
        let mut data = Vec::new();
        for chunk in chunks.by_ref() {
            data.push((chunk[0], chunk[1]));
        }
        if !chunks.remainder().is_empty() {
            return Err(FromBytesError::OddPairItemCount);
        }

        Ok(data)
    }
}

impl<'a, F> Format<F> for Vec<(&'a CStr, &'a CStr)>
where
    &'a CStr: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let mut is_first = true;
        for (k, v) in self {
            if is_first {
                is_first = false;
            } else {
                fmt.write_char(';')?;
            }

            k.format(fmt)?;
            fmt.write_char('=')?;
            v.format(fmt)?;
        }

        Ok(())
    }
}

impl<'a> Borrowed for Vec<(&'a CStr, &'a CStr)> {
    type Owned = Vec<(CString, CString)>;
}

impl Borrow for Vec<(CString, CString)> {
    type Borrowed<'a> = Vec<(&'a CStr, &'a CStr)>
    where
        Self: 'a;

    fn borrow(&self) -> Self::Borrowed<'_> {
        self.iter()
            .map(|(k, v)| (k.as_c_str(), v.as_c_str()))
            .collect()
    }
}

pub mod serde {
    #[allow(dead_code)]
    pub mod cstr_pair_array {
        use crate::types::utf_chunked::UtfChunked;
        use serde::{Serialize, Serializer};
        use std::ffi::CStr;

        pub fn serialize<S: Serializer>(arr: &[(&CStr, &CStr)], ser: S) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks: Vec<_> = arr
                    .iter()
                    .map(|(k, v)| {
                        (
                            UtfChunked::from(k.to_bytes()),
                            UtfChunked::from(v.to_bytes()),
                        )
                    })
                    .collect();
                chunks.serialize(ser)
            } else {
                arr.serialize(ser)
            }
        }
    }

    pub mod cstr_pair_array_option {
        use crate::types::utf_chunked::UtfChunked;
        use serde::{Serialize, Serializer};
        use std::ffi::CStr;

        pub fn serialize<S: Serializer>(
            arr: &Option<Vec<(&CStr, &CStr)>>,
            ser: S,
        ) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks: Option<Vec<_>> = arr.as_ref().map(|arr| {
                    arr.iter()
                        .map(|(k, v)| {
                            (
                                UtfChunked::from(k.to_bytes()),
                                UtfChunked::from(v.to_bytes()),
                            )
                        })
                        .collect()
                });
                chunks.serialize(ser)
            } else {
                arr.serialize(ser)
            }
        }
    }

    pub mod cstr_pair_array_option_owned {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use std::ffi::CString;

        pub fn serialize<S: Serializer>(
            arr: &Option<Vec<(CString, CString)>>,
            ser: S,
        ) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks: Option<Vec<_>> = arr.as_ref().map(|arr| {
                    arr.iter()
                        .map(|(k, v)| {
                            (
                                UtfChunked::from(k.to_bytes()),
                                UtfChunked::from(v.to_bytes()),
                            )
                        })
                        .collect()
                });
                chunks.serialize(ser)
            } else {
                arr.serialize(ser)
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            de: D,
        ) -> Result<Option<Vec<(CString, CString)>>, D::Error> {
            let chunks: Option<Vec<(OwnedUtfChunked, OwnedUtfChunked)>> =
                Deserialize::deserialize(de)?;
            let s: Result<Option<Vec<(CString, CString)>>, D::Error> = chunks
                .map(|chunks| {
                    chunks
                        .into_iter()
                        .map(|(k, v)| {
                            match (
                                CString::new(k.into_vec())
                                    .map_err(|e| D::Error::custom(e.to_string())),
                                CString::new(v.into_vec())
                                    .map_err(|e| D::Error::custom(e.to_string())),
                            ) {
                                (Ok(k), Ok(v)) => Ok((k, v)),
                                (Err(e), _) => Err(e),
                                (_, Err(e)) => Err(e),
                            }
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
    fn test_str_pair_array() {
        let arr = vec![(
            CStr::from_bytes_until_nul(b"foo\0").unwrap(),
            CStr::from_bytes_until_nul(b"bar\0").unwrap(),
        )];

        let mut binary = Vec::new();
        arr.write(&mut binary).unwrap();

        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), b"foo\0bar\0".as_slice());

        let mut buf = binary.as_slice();
        let loaded = <Vec<(&CStr, &CStr)>>::from_bytes(&mut buf).unwrap();

        assert_eq!(arr, loaded)
    }

    #[test]
    fn test_str_pair_array_odd() {
        let mut buf = b"foo\0bar\0baz\0".as_slice();
        assert!(<Vec<(&CStr, &CStr)>>::from_bytes(&mut buf).is_err());
    }
}
