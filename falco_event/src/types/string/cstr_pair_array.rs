use crate::fields::{FromBytes, FromBytesError, ToBytes};
use crate::types::string::cstr::CStrFormatter;
use crate::types::string::cstr_array::CStrArrayIter;
use crate::types::CStrArray;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter, Write as _};
use std::io::Write;

#[derive(Copy, Clone)]
pub struct CStrPairArray<'a>(CStrArray<'a>);

pub struct CStrPairArrayIter<'a>(CStrArrayIter<'a>);

impl<'a> Iterator for CStrPairArrayIter<'a> {
    type Item = (&'a CStr, &'a CStr);

    fn next(&mut self) -> Option<Self::Item> {
        let k = self.0.next()?;
        let v = self.0.next()?;
        Some((k, v))
    }
}

impl<'a> CStrPairArray<'a> {
    pub fn iter(&self) -> CStrPairArrayIter<'a> {
        CStrPairArrayIter(self.0.iter())
    }
}

impl<'a> FromBytes<'a> for CStrPairArray<'a> {
    #[inline]
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        let nuls = buf.iter().filter(|b| **b == 0).count();
        if !nuls.is_multiple_of(2) {
            return Err(FromBytesError::OddPairItemCount);
        }
        let array = CStrArray::from_bytes(buf)?;
        Ok(Self(array))
    }
}

impl<'a> ToBytes for CStrPairArray<'a> {
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
        &[] as &[u8]
    }
}

impl Debug for CStrPairArray<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut is_first = true;
        for (k, v) in self.iter() {
            if is_first {
                is_first = false;
            } else {
                f.write_char(';')?;
            }
            Debug::fmt(&CStrFormatter(k), f)?;
            f.write_char('=')?;
            Debug::fmt(&CStrFormatter(v), f)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::FromBytes;
    use crate::fields::ToBytes;
    use crate::types::CStrPairArray;

    #[test]
    fn test_str_pair_array() {
        let binary = b"foo\0bar\0".as_slice();
        let pair_array = CStrPairArray::from_bytes(&mut &*binary).unwrap();

        let mut iter = pair_array.iter();
        assert_eq!(iter.next(), Some((c"foo", c"bar")));
        assert_eq!(iter.next(), None);

        let mut serialized = Vec::new();
        pair_array.write(&mut serialized).unwrap();
        assert_eq!(serialized.as_slice(), binary);
    }

    #[test]
    fn test_str_pair_array_odd() {
        let binary = b"foo\0bar\0baz\0".as_slice();
        assert!(CStrPairArray::from_bytes(&mut &*binary).is_err());
    }
}
