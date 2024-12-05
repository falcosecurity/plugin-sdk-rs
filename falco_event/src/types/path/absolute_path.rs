use crate::event_derive::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::{Borrow, Borrowed};
use std::ffi::CStr;
use std::fmt::Formatter;
use std::io::Write;
use typed_path::{UnixPath, UnixPathBuf};

impl<'a> FromBytes<'a> for &'a UnixPath {
    fn from_bytes(buf: &mut &'a [u8]) -> FromBytesResult<Self> {
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

impl<F> Format<F> for &UnixPath
where
    for<'a> &'a [u8]: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let bytes = self.as_bytes();
        bytes.format(fmt)
    }
}

impl Borrowed for UnixPath {
    type Owned = UnixPathBuf;
}

impl Borrow for UnixPathBuf {
    type Borrowed<'a> = &'a UnixPath;

    fn borrow(&self) -> Self::Borrowed<'_> {
        self.as_path()
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    pub mod unix_path {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use typed_path::{UnixPath, UnixPathBuf};

        pub fn serialize<S: Serializer>(path: &UnixPath, ser: S) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks = UtfChunked::from(path.as_bytes());
                chunks.serialize(ser)
            } else {
                path.as_bytes().serialize(ser)
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<UnixPathBuf, D::Error> {
            let chunks: OwnedUtfChunked = Deserialize::deserialize(de)?;
            Ok(UnixPathBuf::from(chunks.into_vec()))
        }
    }

    pub mod unix_path_option {
        use crate::types::utf_chunked::UtfChunked;
        use serde::{Serialize, Serializer};
        use typed_path::UnixPath;

        pub fn serialize<S: Serializer>(
            path: &Option<&UnixPath>,
            ser: S,
        ) -> Result<S::Ok, S::Error> {
            if ser.is_human_readable() {
                let chunks = path.as_ref().map(|path| UtfChunked::from(path.as_bytes()));
                chunks.serialize(ser)
            } else {
                path.map(|p| p.as_bytes()).serialize(ser)
            }
        }
    }

    pub mod unix_path_option_owned {
        use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use typed_path::UnixPathBuf;

        pub fn serialize<S: Serializer>(
            path: &Option<UnixPathBuf>,
            ser: S,
        ) -> Result<S::Ok, S::Error> {
            let chunks = path.as_ref().map(|path| UtfChunked::from(path.as_bytes()));
            chunks.serialize(ser)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            de: D,
        ) -> Result<Option<UnixPathBuf>, D::Error> {
            let chunks: Option<OwnedUtfChunked> = Deserialize::deserialize(de)?;
            Ok(chunks.map(|c| UnixPathBuf::from(c.into_vec())))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event_derive::{FromBytes, ToBytes};
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

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_absolute_path() {
        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(transparent)]
        struct SerPathBuf(#[serde(with = "super::serde::unix_path")] UnixPathBuf);

        let path = SerPathBuf(UnixPathBuf::from("/foo"));

        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(json, "\"/foo\"");

        let path2: SerPathBuf = serde_json::from_str(&json).unwrap();
        assert_eq!(path2.0, path.0);

        let json2 = serde_json::to_string(&path2).unwrap();
        assert_eq!(json, json2);
    }
}
