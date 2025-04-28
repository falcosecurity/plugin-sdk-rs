use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::fmt::{Debug, Formatter, Write as _};
use std::io::Write;

impl<'a> FromBytes<'a> for &'a [u8] {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        Ok(std::mem::take(buf))
    }
}

impl ToBytes for &[u8] {
    fn binary_size(&self) -> usize {
        self.len()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self)
    }

    fn default_repr() -> impl ToBytes {
        &[] as &[u8]
    }
}

/// Falco-style byte buffer formatter
///
/// The default [`Debug`] impl prints out the buffer as an ASCII string, replacing non-printable
/// characters with dots (`.`).
///
/// The hex debug implementation (`{:x?}`) generates a hex dump of the whole buffer.
pub struct ByteBufFormatter<'a>(pub &'a [u8]);

impl Debug for ByteBufFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // https://users.rust-lang.org/t/idiomatic-to-implement-the-debug-trait-for-x-syntax/84955
        #[allow(deprecated)]
        if f.flags() & 16 != 0 {
            let mut first = true;
            for c in self.0 {
                if first {
                    first = false;
                } else {
                    write!(f, " ")?;
                }
                write!(f, "{:02x}", *c)?;
            }
        } else {
            for c in self.0 {
                let c = *c;
                if !(b' '..=0x7e).contains(&c) {
                    f.write_char('.')?;
                } else {
                    f.write_char(c as char)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{FromBytes, ToBytes};

    #[test]
    fn test_bytebuf() {
        let data = b"foo".as_slice();
        let mut binary = Vec::new();

        data.write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "foo".as_bytes());

        let mut buf = binary.as_slice();
        let loaded = <&[u8]>::from_bytes(&mut buf).unwrap();
        assert_eq!(loaded, "foo".as_bytes());
    }

    #[test]
    fn test_bytebuf_inner_nul() {
        let data = b"f\0oo".as_slice();
        let mut binary = Vec::new();

        data.write(&mut binary).unwrap();
        hexdump::hexdump(binary.as_slice());

        assert_eq!(binary.as_slice(), "f\0oo".as_bytes());

        let mut buf = binary.as_slice();
        let loaded = <&[u8]>::from_bytes(&mut buf).unwrap();
        assert_eq!(loaded, "f\0oo".as_bytes());
    }
}
