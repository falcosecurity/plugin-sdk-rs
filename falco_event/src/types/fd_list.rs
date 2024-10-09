use std::fmt::{Debug, Formatter};
use std::io::Write;

use crate::fields::event_flags::PT_FLAGS16_file_flags;
use crate::fields::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};

/// A list of file descriptors with flags
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct FdList(pub Vec<(u64, PT_FLAGS16_file_flags)>);

impl<F> Format<F> for FdList
where
    PT_FLAGS16_file_flags: Format<F>,
{
    fn format(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for item in &self.0 {
            if first {
                first = false;
                write!(f, "[")?;
            } else {
                write!(f, " ")?;
            }
            write!(f, "{}:", item.0)?;
            // TODO: this could use a shorter repr (without the bits)
            item.1.format(f)?;
        }

        write!(f, "]")?;
        Ok(())
    }
}

impl ToBytes for FdList {
    fn binary_size(&self) -> usize {
        2 + (8 + 2) * self.0.len()
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_u16::<NativeEndian>(self.0.len() as u16)?;
        for item in &self.0 {
            item.0.write(&mut writer)?;
            item.1.write(&mut writer)?;
        }

        Ok(())
    }

    fn default_repr() -> impl ToBytes {
        0u16
    }
}

impl FromBytes<'_> for FdList {
    fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self> {
        let mut fds = Vec::new();
        let len = buf.read_u16::<NativeEndian>()?;
        for _ in 0..len as usize {
            let fd = u64::from_bytes(buf)?;
            let flags = PT_FLAGS16_file_flags::from_bytes(buf)?;
            fds.push((fd, flags))
        }

        Ok(Self(fds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_list() {
        let fdlist = FdList(vec![(13, PT_FLAGS16_file_flags::O_RDONLY)]);

        dbg!(&fdlist);

        let mut binary = Vec::new();
        fdlist.write(&mut binary).unwrap();

        assert_eq!(
            binary.as_slice(),
            b"\x01\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x01\x00".as_slice()
        );

        let mut buf = binary.as_slice();

        let fdlist2 = <FdList>::from_bytes(&mut buf).unwrap();

        assert_eq!(fdlist, fdlist2)
    }

    #[test]
    fn test_serde_fd_list() {
        let fd_list = FdList(vec![
            (13, PT_FLAGS16_file_flags::O_RDONLY),
            (15, PT_FLAGS16_file_flags::O_WRONLY),
        ]);
        let json = serde_json::to_string(&fd_list).unwrap();

        assert_eq!(json, r#"[[13,"O_RDONLY"],[15,"O_WRONLY"]]"#);
        let fd_list2: FdList = serde_json::from_str(&json).unwrap();

        assert_eq!(fd_list, fd_list2)
    }
}
