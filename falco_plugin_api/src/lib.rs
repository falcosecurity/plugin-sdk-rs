pub use ffi::*;
use std::ffi::CStr;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
mod ffi;

pub const SCHEMA_VERSION: &CStr = {
    match CStr::from_bytes_with_nul(
        concat!(include_str!("../plugin/SCHEMA_VERSION"), "\0").as_bytes(),
    ) {
        Ok(s) => s,
        Err(_) => panic!("Failed to parse SCHEMA_VERSION: embedded null byte in string"),
    }
};
