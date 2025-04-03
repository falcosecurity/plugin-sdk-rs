#![allow(non_camel_case_types)]

pub use crate::fields::dynamic_params::*;
pub use crate::fields::event_flags::*;
pub use crate::types::Bool as PT_BOOL;
pub use crate::types::Fd as PT_FD;
pub use crate::types::FdList as PT_FDLIST;
pub use crate::types::Gid as PT_GID;
pub use crate::types::IpNet as PT_IPNET;
pub use crate::types::Ipv4Net as PT_IPV4NET;
pub use crate::types::Ipv6Net as PT_IPV6NET;
pub use crate::types::Pid as PT_PID;
pub use crate::types::Port as PT_PORT;
pub use crate::types::RelativePath as PT_FSRELPATH;
pub use crate::types::SigSet as PT_SIGSET;
pub use crate::types::SigType as PT_SIGTYPE;
pub use crate::types::SockAddr as PT_SOCKADDR;
pub use crate::types::SockFamily as PT_SOCKFAMILY;
pub use crate::types::SockTuple as PT_SOCKTUPLE;
pub use crate::types::SyscallId as PT_SYSCALLID;
pub use crate::types::SyscallResult as PT_ERRNO;
pub use crate::types::Uid as PT_UID;
use std::ffi::CStr;
pub use std::net::IpAddr as PT_IPADDR;
pub use std::net::Ipv4Addr as PT_IPV4ADDR;
pub use std::net::Ipv6Addr as PT_IPV6ADDR;
pub use std::time::Duration as PT_RELTIME;
pub use std::time::SystemTime as PT_ABSTIME;
pub use typed_path::UnixPath as PT_FSPATH;

/// Signed 8-bit value ([i8])
pub type PT_INT8 = i8;
/// Signed 16-bit value ([i16])
pub type PT_INT16 = i16;
/// Signed 32-bit value ([i32])
pub type PT_INT32 = i32;
/// Signed 64-bit value ([i64])
pub type PT_INT64 = i64;
/// Unsigned 8-bit value ([u8])
pub type PT_UINT8 = u8;
/// Unsigned 16-bit value ([u16])
pub type PT_UINT16 = u16;
/// Unsigned 32-bit value ([u32])
pub type PT_UINT32 = u32;
/// Unsigned 64-bit value ([u64])
pub type PT_UINT64 = u64;
/// C-style string ([CStr])
pub type PT_CHARBUF = CStr;
/// Arbitrary byte buffer (`[u8]`)
pub type PT_BYTEBUF = [u8];
/// Array of C-style strings (`Vec<&CStr>`)
pub type PT_CHARBUFARRAY<'a> = Vec<&'a CStr>;
/// Array of pairs of C-style strings (`Vec<(&CStr, &CStr)>`)
pub type PT_CHARBUF_PAIR_ARRAY<'a> = Vec<(&'a CStr, &'a CStr)>;

// PT_DOUBLE = 33, /* this is a double precision floating point number. */ // this remains unimplemented
