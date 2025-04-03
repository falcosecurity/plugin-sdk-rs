use falco_event::fields::types::PT_IPNET;
use falco_event::fields::ToBytes;
use falco_plugin_api::{
    ss_plugin_byte_buffer, ss_plugin_extract_field, ss_plugin_field_type_FTYPE_ABSTIME,
    ss_plugin_field_type_FTYPE_BOOL, ss_plugin_field_type_FTYPE_IPADDR,
    ss_plugin_field_type_FTYPE_IPNET, ss_plugin_field_type_FTYPE_RELTIME,
    ss_plugin_field_type_FTYPE_STRING, ss_plugin_field_type_FTYPE_UINT64,
};
use num_derive::FromPrimitive;
use std::ffi::{c_void, CString};
use std::net::IpAddr;
use std::ptr::null_mut;
use std::time::{Duration, SystemTime};

#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum ExtractFieldTypeId {
    /// A 64bit unsigned integer.
    U64 = ss_plugin_field_type_FTYPE_UINT64,
    /// A printable buffer of bytes, NULL terminated
    String = ss_plugin_field_type_FTYPE_STRING,
    /// A relative time. Seconds * 10^9  + nanoseconds. 64bit.
    RelTime = ss_plugin_field_type_FTYPE_RELTIME,
    /// An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit.
    AbsTime = ss_plugin_field_type_FTYPE_ABSTIME,
    /// A boolean value, 4 bytes.
    Bool = ss_plugin_field_type_FTYPE_BOOL,
    /// Either an IPv4 or IPv6 address. The length indicates which one it is.
    IpAddr = ss_plugin_field_type_FTYPE_IPADDR,
    /// Either an IPv4 or IPv6 network. The length indicates which one it is.
    /// The field encodes only the IP address, so this differs from IPADDR,
    /// from the way the framework perform runtime checks and comparisons.
    IpNet = ss_plugin_field_type_FTYPE_IPNET,
}

pub trait Extract {
    const IS_LIST: bool;
    const TYPE_ID: ExtractFieldTypeId;

    fn extract_to(
        &self,
        req: &mut ss_plugin_extract_field,
        storage: &bumpalo::Bump,
    ) -> Result<(), std::io::Error>;
}

mod direct {
    use super::*;

    pub(super) fn extract_one<T: ToBytes>(
        val: &T,
        storage: &bumpalo::Bump,
    ) -> Result<(*mut c_void, u64), std::io::Error> {
        let mut buf = bumpalo::collections::Vec::new_in(storage);
        val.write(&mut buf)?;
        Ok((buf.as_mut_ptr().cast(), 1))
    }

    pub(super) fn extract_many<T: ToBytes>(
        val: &[T],
        storage: &bumpalo::Bump,
    ) -> Result<(*mut c_void, u64), std::io::Error> {
        let mut buf = bumpalo::collections::Vec::new_in(storage);
        for item in val.iter() {
            item.write(&mut buf)?;
        }
        Ok((buf.as_mut_ptr().cast(), val.len() as u64))
    }
}

mod by_ref {
    use super::*;

    pub(super) fn extract_one<T, U>(
        val: &T,
        storage: &bumpalo::Bump,
    ) -> Result<(*mut c_void, u64), std::io::Error>
    where
        for<'a> &'a U: ToBytes,
        T: AsRef<U>,
        U: ?Sized,
    {
        let mut buf = bumpalo::collections::Vec::new_in(storage);
        val.as_ref().write(&mut buf)?;

        let ptr_buf = storage.alloc(buf.as_ptr());
        Ok((ptr_buf as *mut _ as *mut _, 1))
    }

    pub(super) fn extract_many<T, U>(
        val: &[T],
        storage: &bumpalo::Bump,
    ) -> Result<(*mut c_void, u64), std::io::Error>
    where
        for<'a> &'a U: ToBytes,
        T: AsRef<U>,
        U: ?Sized,
    {
        let mut sizes = bumpalo::collections::Vec::new_in(storage);
        sizes.reserve(val.len());

        let mut buf = bumpalo::collections::Vec::new_in(storage);
        for item in val.iter() {
            item.as_ref().write(&mut buf)?;
            sizes.push(item.as_ref().binary_size());
        }

        let mut ptr_buf = bumpalo::collections::Vec::new_in(storage);
        ptr_buf.reserve(sizes.len());
        let mut ptr = buf.as_ptr();
        for size in sizes {
            ptr_buf.push(ptr);
            ptr = unsafe { ptr.add(size) };
        }
        Ok((ptr_buf.as_mut_ptr().cast(), val.len() as u64))
    }
}

mod by_bytebuf {
    use super::*;

    pub(super) fn extract_one<T: ToBytes>(
        val: &T,
        storage: &bumpalo::Bump,
    ) -> Result<(*mut c_void, u64), std::io::Error> {
        let mut buf = bumpalo::collections::Vec::new_in(storage);
        val.write(&mut buf)?;

        let bb_buf = storage.alloc(ss_plugin_byte_buffer {
            len: val.binary_size() as u32,
            ptr: buf.as_ptr().cast(),
        });

        Ok((bb_buf as *mut _ as *mut _, 1))
    }

    pub(super) fn extract_many<T: ToBytes>(
        val: &[T],
        storage: &bumpalo::Bump,
    ) -> Result<(*mut c_void, u64), std::io::Error> {
        let mut sizes = bumpalo::collections::Vec::new_in(storage);
        sizes.reserve(val.len());

        let mut buf = bumpalo::collections::Vec::new_in(storage);
        for item in val.iter() {
            item.write(&mut buf)?;
            sizes.push(item.binary_size());
        }

        let mut bb_buf = bumpalo::collections::Vec::new_in(storage);
        bb_buf.reserve(sizes.len());

        let mut ptr = buf.as_ptr();
        for size in sizes {
            bb_buf.push(ss_plugin_byte_buffer {
                len: size as u32,
                ptr: ptr.cast(),
            });
            ptr = unsafe { ptr.add(size) };
        }
        Ok((bb_buf.as_mut_ptr().cast(), val.len() as u64))
    }
}

macro_rules! extract {
    ($ty:ty : $strategy_mod:ident => $type_id:expr) => {
        impl Extract for $ty {
            const IS_LIST: bool = false;
            const TYPE_ID: ExtractFieldTypeId = $type_id;

            fn extract_to(
                &self,
                req: &mut ss_plugin_extract_field,
                storage: &bumpalo::Bump,
            ) -> Result<(), std::io::Error> {
                let (buf, len) = $strategy_mod::extract_one(self, storage)?;
                req.res.u64_ = buf as *mut _;
                req.res_len = len;
                Ok(())
            }
        }

        impl Extract for Option<$ty> {
            const IS_LIST: bool = false;
            const TYPE_ID: ExtractFieldTypeId = $type_id;

            fn extract_to(
                &self,
                req: &mut ss_plugin_extract_field,
                storage: &bumpalo::Bump,
            ) -> Result<(), std::io::Error> {
                match &self {
                    Some(val) => {
                        let (buf, len) = $strategy_mod::extract_one(val, storage)?;
                        req.res.u64_ = buf as *mut _;
                        req.res_len = len;
                    }
                    None => {
                        req.res.u64_ = null_mut();
                        req.res_len = 0;
                    }
                }
                Ok(())
            }
        }

        impl Extract for Vec<$ty> {
            const IS_LIST: bool = true;
            const TYPE_ID: ExtractFieldTypeId = $type_id;

            fn extract_to(
                &self,
                req: &mut ss_plugin_extract_field,
                storage: &bumpalo::Bump,
            ) -> Result<(), std::io::Error> {
                let (buf, len) = $strategy_mod::extract_many(self.as_slice(), storage)?;
                req.res.u64_ = buf as *mut _;
                req.res_len = len;
                Ok(())
            }
        }

        impl Extract for Option<Vec<$ty>> {
            const IS_LIST: bool = true;
            const TYPE_ID: ExtractFieldTypeId = $type_id;

            fn extract_to(
                &self,
                req: &mut ss_plugin_extract_field,
                storage: &bumpalo::Bump,
            ) -> Result<(), std::io::Error> {
                match &self {
                    Some(val) => {
                        let (buf, len) = $strategy_mod::extract_many(val.as_slice(), storage)?;
                        req.res.u64_ = buf as *mut _;
                        req.res_len = len;
                    }
                    None => {
                        req.res.u64_ = null_mut();
                        req.res_len = 0;
                    }
                }
                Ok(())
            }
        }
    };
}

extract!(u64: direct => ExtractFieldTypeId::U64);
extract!(Duration: direct => ExtractFieldTypeId::RelTime);
extract!(SystemTime: direct => ExtractFieldTypeId::AbsTime);
extract!(bool: direct => ExtractFieldTypeId::Bool);
extract!(CString: by_ref => ExtractFieldTypeId::String);
extract!(IpAddr: by_bytebuf => ExtractFieldTypeId::IpAddr);
extract!(PT_IPNET: by_bytebuf => ExtractFieldTypeId::IpNet);
