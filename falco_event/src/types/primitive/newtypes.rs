use crate::event_derive::format_type;
use crate::fields::{FromBytes, FromBytesResult, ToBytes};
use crate::types::format::Format;
use crate::types::{BorrowDeref, Borrowed};
use std::fmt::{Debug, Formatter};

macro_rules! default_format {
    ($name:ident($repr:ty)) => {
        impl<F> Format<F> for $name
        where
            $repr: Format<F>,
        {
            fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                self.0.format(fmt)
            }
        }
    };
}

macro_rules! newtype {
    ($(#[$attr:meta])* $name:ident($repr:ty)) => {
        $(#[$attr])*
        #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        pub struct $name(pub $repr);

        impl FromBytes<'_> for $name {
            fn from_bytes(buf: &mut &[u8]) -> FromBytesResult<Self>
            where
                Self: Sized,
            {
                Ok(Self(FromBytes::from_bytes(buf)?))
            }
        }

        impl ToBytes for $name {
            fn binary_size(&self) -> usize {
                self.0.binary_size()
            }

            fn write<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
                self.0.write(writer)
            }

            fn default_repr() -> impl ToBytes {
                <$repr>::default_repr()
            }
        }

        impl Borrowed for $name {
            type Owned = Self;
        }

        impl BorrowDeref for $name {
            type Target<'a> = $name;

            fn borrow_deref(&self) -> Self::Target<'_> {
                *self
            }
        }
    };
}

newtype!(
    /// Syscall result
    #[derive(Debug)]
    SyscallResult(i64)
);

#[cfg(target_os = "linux")]
impl<F> Format<F> for SyscallResult
where
    i64: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        if self.0 < 0 {
            let errno = nix::errno::Errno::from_raw(-self.0 as i32);
            if errno == nix::errno::Errno::UnknownErrno {
                // always format errors as decimal
                <i64 as Format<format_type::PF_DEC>>::format(&self.0, fmt)
            } else {
                write!(fmt, "{}({:?})", self.0, errno)
            }
        } else {
            self.0.format(fmt)
        }
    }
}

// not on Linux, we don't have the Linux errnos without maintaining the list ourselves
#[cfg(not(target_os = "linux"))]
impl<F> Format<F> for SyscallResult
where
    i64: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        if self.0 < 0 {
            // always format errors as decimal
            <i64 as Format<format_type::PF_DEC>>::format(&self.0, fmt)
        } else {
            self.0.format(fmt)
        }
    }
}

newtype!(
    /// A system call number
    #[derive(Debug)]
    SyscallId(u16)
);
default_format!(SyscallId(u16));

newtype!(
    /// A signal number
    #[derive(Debug)]
    SigType(u8)
);

impl<F> Format<F> for SigType
where
    u8: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        self.0.format(fmt)?;

        #[cfg(target_os = "linux")]
        {
            let sig = nix::sys::signal::Signal::try_from(self.0 as i32);
            if let Ok(sig) = sig {
                write!(fmt, "({sig:?})")?;
            }
        }

        Ok(())
    }
}

newtype!(
    /// File descriptor
    #[derive(Debug)]
    Fd(i64)
);

impl<F> Format<F> for Fd
where
    i64: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        if self.0 == -100 {
            fmt.write_str("AT_FDCWD")
        } else {
            self.0.format(fmt)
        }
    }
}

newtype!(
    /// Process or thread id
    #[derive(Debug)]
    Pid(i64)
);
default_format!(Pid(i64));

newtype!(
    /// User id
    #[derive(Debug)]
    Uid(u32)
);
default_format!(Uid(u32));

newtype!(
    /// Group id
    #[derive(Debug)]
    Gid(u32)
);
default_format!(Gid(u32));

newtype!(
    /// Signal set (bitmask of signals, only the lower 32 bits are used)
    #[derive(Debug)]
    SigSet(u32)
);

impl<F> Format<F> for SigSet
where
    SigType: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        <u32 as Format<format_type::PF_HEX>>::format(&self.0, fmt)?;
        if self.0 != 0 {
            let mut first = false;
            for sig in 0..32 {
                if (self.0 & (1 << sig)) != 0 {
                    if first {
                        write!(fmt, "(")?;
                        first = false;
                    } else {
                        write!(fmt, ",")?;
                    }
                    let sig_type = SigType(sig);
                    sig_type.format(fmt)?;
                }
            }
            write!(fmt, ")")?;
        }

        Ok(())
    }
}

newtype!(
    /// IP port number
    ///
    /// This looks unused
    #[derive(Debug)]
    Port(u16)
);
default_format!(Port(u16));

newtype!(
    /// Layer 4 protocol (tcp/udp)
    ///
    /// This looks unused
    #[derive(Debug)]
    L4Proto(u8)
);
default_format!(L4Proto(u8));

newtype!(
    /// Socket family (`PPM_AF_*`)
    ///
    /// This looks unused
    #[derive(Debug)]
    SockFamily(u8)
);
default_format!(SockFamily(u8));

newtype!(
    /// Boolean value (0/1)
    ///
    /// This looks unused
    #[derive(Debug)]
    Bool(u32)
);

impl<F> Format<F> for Bool {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        match self.0 {
            0 => fmt.write_str("false"),
            1 => fmt.write_str("true"),
            n => write!(fmt, "true({n})"),
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use crate::types::SyscallResult;

    #[test]
    fn test_serde_newtype() {
        let val = SyscallResult(-2);
        let json = serde_json::to_string(&val).unwrap();

        assert_eq!(json, "-2");
        let val2: SyscallResult = serde_json::from_str(&json).unwrap();
        assert_eq!(val, val2);
    }
}
