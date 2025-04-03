use crate::event_derive::{CStrFormatter, FromBytes, FromBytesError, FromBytesResult, ToBytes};
use std::ffi::CStr;
use std::fmt::{Debug, Formatter, Write as _};
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

pub struct CStrPairArrayFormatter<'a, T: AsRef<CStr>>(pub &'a Vec<(T, T)>);

impl<T: AsRef<CStr>> Debug for CStrPairArrayFormatter<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut is_first = true;
        for (k, v) in self.0 {
            if is_first {
                is_first = false;
            } else {
                f.write_char(';')?;
            }
            Debug::fmt(&CStrFormatter(k.as_ref()), f)?;
            f.write_char('=')?;
            Debug::fmt(&CStrFormatter(v.as_ref()), f)?;
        }

        Ok(())
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
