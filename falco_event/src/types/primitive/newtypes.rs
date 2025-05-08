use crate::fields::{FromBytes, FromBytesError, ToBytes};
use std::fmt::{Debug, Formatter, LowerHex};

macro_rules! default_debug {
    ($name:ident) => {
        impl Debug for $name {
            fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                Debug::fmt(&self.0, fmt)
            }
        }
    };
}

macro_rules! newtype {
    ($(#[$attr:meta])* $name:ident($repr:ty)) => {
        $(#[$attr])*
        #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
        pub struct $name(pub $repr);

        impl FromBytes<'_> for $name {
            fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError>
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
    };
}

newtype!(
    /// Syscall result
    SyscallResult(i64)
);

impl Debug for SyscallResult {
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if self.0 < 0 {
            let errno = nix::errno::Errno::from_raw(-self.0 as i32);
            if errno == nix::errno::Errno::UnknownErrno {
                // always format errors as decimal
                write!(f, "{}", self.0)
            } else {
                write!(f, "{}({:?})", self.0, errno)
            }
        } else {
            Debug::fmt(&self.0, f)
        }
    }

    // not on Linux, we don't have the Linux errnos without maintaining the list ourselves
    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if self.0 < 0 {
            // always format errors as decimal
            write!(f, "{}", self.0)
        } else {
            Debug::fmt(&self.0, f)
        }
    }
}

impl LowerHex for SyscallResult {
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if self.0 < 0 {
            let errno = nix::errno::Errno::from_raw(-self.0 as i32);
            if errno == nix::errno::Errno::UnknownErrno {
                // always format errors as decimal
                write!(f, "{}", self.0)
            } else {
                write!(f, "{}({:?})", self.0, errno)
            }
        } else {
            LowerHex::fmt(&self.0, f)
        }
    }

    // not on Linux, we don't have the Linux errnos without maintaining the list ourselves
    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if self.0 < 0 {
            // always format errors as decimal
            write!(f, "{}", self.0)
        } else {
            LowerHex::fmt(&self.0, f)
        }
    }
}

#[cfg(test)]
mod syscall_result_tests {
    use crate::types::SyscallResult;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_fmt_syscall_result() {
        assert_eq!(format!("{:?}", SyscallResult(0)), "0");
        assert_eq!(format!("{:?}", SyscallResult(1024)), "1024");
        assert_eq!(format!("{:?}", SyscallResult(-2)), "-2(ENOENT)");
        assert_eq!(format!("{:?}", SyscallResult(-28)), "-28(ENOSPC)");
        assert_eq!(format!("{:?}", SyscallResult(-1024)), "-1024");

        assert_eq!(format!("{:#x}", SyscallResult(0)), "0x0");
        assert_eq!(format!("{:#x}", SyscallResult(1024)), "0x400");
        assert_eq!(format!("{:#x}", SyscallResult(-2)), "-2(ENOENT)");
        assert_eq!(format!("{:#x}", SyscallResult(-28)), "-28(ENOSPC)");
        assert_eq!(format!("{:#x}", SyscallResult(-1024)), "-1024");
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_fmt_syscall_result() {
        assert_eq!(format!("{:?}", SyscallResult(0)), "0");
        assert_eq!(format!("{:?}", SyscallResult(1024)), "1024");
        assert_eq!(format!("{:?}", SyscallResult(-2)), "-2");
        assert_eq!(format!("{:?}", SyscallResult(-28)), "-28");
        assert_eq!(format!("{:?}", SyscallResult(-1024)), "-1024");

        assert_eq!(format!("{:#x}", SyscallResult(0)), "0x0");
        assert_eq!(format!("{:#x}", SyscallResult(1024)), "0x400");
        assert_eq!(format!("{:#x}", SyscallResult(-2)), "-2");
        assert_eq!(format!("{:#x}", SyscallResult(-28)), "-28");
        assert_eq!(format!("{:#x}", SyscallResult(-1024)), "-1024");
    }
}

newtype!(
    /// A system call number
    SyscallId(u16)
);
default_debug!(SyscallId);

newtype!(
    /// A signal number
    SigType(u8)
);

impl Debug for SigType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)?;

        #[cfg(target_os = "linux")]
        {
            let sig = nix::sys::signal::Signal::try_from(self.0 as i32);
            if let Ok(sig) = sig {
                write!(f, "({sig:?})")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod sig_tests {
    use crate::types::SigType;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_sig_fmt() {
        let formatted = format!("{:?}", SigType(1));
        assert_eq!(formatted, "1(SIGHUP)");
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_sig_fmt() {
        let formatted = format!("{:?}", SigType(1));
        assert_eq!(formatted, "1");
    }
}

newtype!(
    /// File descriptor
    Fd(i64)
);

impl Debug for Fd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0 == -100 {
            f.write_str("AT_FDCWD")
        } else {
            Debug::fmt(&self.0, f)
        }
    }
}

#[cfg(test)]
mod fd_tests {
    use crate::types::Fd;

    #[test]
    fn test_fd_fmt() {
        assert_eq!(format!("{:?}", Fd(10)), "10");
        assert_eq!(format!("{:?}", Fd(-100)), "AT_FDCWD");
    }
}

newtype!(
    /// Process or thread id
    Pid(i64)
);
default_debug!(Pid);

newtype!(
    /// User id
    Uid(u32)
);
default_debug!(Uid);

newtype!(
    /// Group id
    Gid(u32)
);
default_debug!(Gid);

newtype!(
    /// Signal set (bitmask of signals, only the lower 32 bits are used)
    SigSet(u32)
);

impl SigSet {
    /// Iterate over all signals in this set
    pub fn iter(&self) -> impl Iterator<Item = SigType> + use<> {
        let mask = self.0;
        (0..32u8)
            .filter(move |sig| mask & (1u32 << sig) != 0)
            .map(SigType)
    }
}

impl Debug for SigSet {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{:#2x}", self.0)?;
        if self.0 != 0 {
            let mut first = true;
            for sig in self.iter() {
                if first {
                    write!(fmt, "(")?;
                    first = false;
                } else {
                    write!(fmt, ",")?;
                }
                write!(fmt, "{:?}", sig)?;
            }
            write!(fmt, ")")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod sigset_tests {
    use crate::types::SigSet;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_sigset() {
        let signals = (1 << 2) | // SIGINT
            (1 << 9); // SIGKILL

        let formatted = format!("{:?}", SigSet(signals));
        assert_eq!(formatted, "0x204(2(SIGINT),9(SIGKILL))");
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_sigset() {
        let signals = (1 << 2) | // SIGINT
            (1 << 9); // SIGKILL

        let formatted = format!("{:?}", SigSet(signals));
        assert_eq!(formatted, "0x204(2,9)");
    }
}

newtype!(
    /// IP port number
    ///
    /// This looks unused
    Port(u16)
);
default_debug!(Port);

newtype!(
    /// Layer 4 protocol (tcp/udp)
    ///
    /// This looks unused
    L4Proto(u8)
);
default_debug!(L4Proto);

newtype!(
    /// Socket family (`PPM_AF_*`)
    ///
    /// This looks unused
    #[derive(Debug)]
    SockFamily(u8)
);

newtype!(
    /// Boolean value (0/1)
    ///
    /// This looks unused
    Bool(u32)
);

impl Debug for Bool {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("false"),
            1 => f.write_str("true"),
            n => write!(f, "true({n})"),
        }
    }
}

#[cfg(test)]
mod bool_tests {
    use crate::types::Bool;

    #[test]
    fn test_bool() {
        assert_eq!(format!("{:?}", Bool(0)), "false");
        assert_eq!(format!("{:?}", Bool(1)), "true");
        assert_eq!(format!("{:?}", Bool(10)), "true(10)");
    }
}
