//! # A collection of tests for [`falco_plugin`]
//!
//! This crate isn't really intended for public use, except maybe as a collection of sample plugins.

#[cfg(have_libsinsp)]
pub mod ffi;

use std::ffi::CStr;

pub mod native;

pub mod common;
pub mod plugin_collection;

pub use common::*;

pub fn init_plugin<D: TestDriver>(
    api: &'static falco_plugin::api::plugin_api,
    config: &CStr,
) -> anyhow::Result<(D, D::Plugin)> {
    let mut driver = D::new()?;
    let plugin = driver.register_plugin(api, config)?;

    Ok((driver, plugin))
}

#[macro_export]
macro_rules! instantiate_tests {
    ($($func:ident);*) => {
        mod native {
            $(
            #[test]
            fn $func() {
                super::$func::<$crate::native::Driver>()
            }
            )*
        }

        #[cfg(have_libsinsp)]
        mod ffi {
            $(
            #[test]
            fn $func() {
                super::$func::<$crate::ffi::Driver>()
            }
            )*
        }
    };
}

#[macro_export]
macro_rules! instantiate_sinsp_tests {
    ($($func:ident);*) => {
        #[cfg(have_libsinsp)]
        mod ffi {
            $(
            #[test]
            fn $func() {
                super::$func::<$crate::ffi::Driver>()
            }
            )*
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::TestDriver;

    fn compile_test<D: TestDriver>() {
        let _ = D::new();
    }

    fn register_null_plugin<D: TestDriver>() {
        let mut driver = D::new().unwrap();
        let res = unsafe { driver.register_plugin_raw(std::ptr::null(), c"") };
        assert!(res.is_err())
    }

    instantiate_tests!(
        compile_test;
        register_null_plugin
    );
}
