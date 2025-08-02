use super::{
    AsPtr, CapturingTestDriver, PlatformData, RawExtractedValue, SavefileTestDriver, ScapStatus,
    TestDriver,
};
use crate::common::{Api, CaptureNotStarted, CaptureStarted, SinspMetric};
use cxx;
use cxx::UniquePtr;
use falco_plugin::event::fields::types::PT_IPNET;
use falco_plugin_runner::ExtractedField;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::ptr::read_unaligned;

#[allow(clippy::missing_safety_doc)]
#[allow(clippy::module_inception)]
#[cxx::bridge]
mod ffi {
    struct SinspEvent {
        rc: i32,
        evt: *mut c_char,
    }

    #[derive(Debug)]
    enum ExtractFieldType {
        String = 9,
        Uint64 = 8,
        Bool = 25,
        RelTime = 20,
        AbsTime = 21,
        IpAddr = 40,
        IpNet = 41,
    }

    struct SinspExtractedField<'a> {
        field_type: ExtractFieldType,
        is_list: bool,
        values: &'a CxxVector<extract_value_t>,
    }

    struct SinspMetric {
        name: UniquePtr<CxxString>,
        value: u64,
    }

    extern "Rust" {
        type Api;
    }

    unsafe extern "C++" {
        include!("falco_plugin_tests/c++/sinsp_test_driver.h");

        type SinspTestDriver;
        type sinsp_plugin;
        type extract_value_t = crate::common::RawExtractedValue;

        fn scap_event(self: &SinspEvent) -> *const c_char;

        fn new_test_driver() -> UniquePtr<SinspTestDriver>;

        unsafe fn register_plugin(
            self: Pin<&mut SinspTestDriver>,
            plugin: *const Api,
            config: *const c_char,
        ) -> Result<SharedPtr<sinsp_plugin>>;

        unsafe fn add_filterchecks(
            self: Pin<&mut SinspTestDriver>,
            plugin: &SharedPtr<sinsp_plugin>,
            source: *const c_char,
        ) -> Result<()>;

        unsafe fn load_capture_file(
            self: Pin<&mut SinspTestDriver>,
            path: *const c_char,
        ) -> Result<()>;

        unsafe fn start_capture(
            self: Pin<&mut SinspTestDriver>,
            name: *const c_char,
            config: *const c_char,
            platform_data: bool,
        ) -> Result<()>;

        fn next(self: Pin<&mut SinspTestDriver>) -> SinspEvent;

        unsafe fn event_field_as_string(
            self: Pin<&mut SinspTestDriver>,
            field_name: *const c_char,
            event: &SinspEvent,
        ) -> Result<UniquePtr<CxxString>>;

        unsafe fn event_field_as_string_with_offsets(
            self: Pin<&mut SinspTestDriver>,
            field_name: *const c_char,
            event: &SinspEvent,
            start: &mut u32,
            length: &mut u32,
        ) -> Result<UniquePtr<CxxString>>;

        unsafe fn extract_event_field(
            self: Pin<&mut SinspTestDriver>,
            field_name: *const c_char,
            event: &SinspEvent,
        ) -> Result<SinspExtractedField<'_>>;

        fn get_metrics(
            self: Pin<&mut SinspTestDriver>,
        ) -> Result<UniquePtr<CxxVector<SinspMetric>>>;
    }

    impl CxxVector<extract_value_t> {}
}

pub struct SinspEvent {
    event: ffi::SinspEvent,
}

impl AsPtr for SinspEvent {
    fn as_ptr(&self) -> *const u8 {
        self.event.scap_event().cast()
    }
}

pub struct SinspPlugin {
    plugin: cxx::SharedPtr<ffi::sinsp_plugin>,
}

impl Debug for SinspPlugin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SinspPlugin")
    }
}

pub struct SinspTestDriver<S> {
    driver: UniquePtr<ffi::SinspTestDriver>,
    state: PhantomData<S>,
}

impl<S> Debug for SinspTestDriver<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SinspTestDriver")
    }
}

impl TestDriver for SinspTestDriver<CaptureNotStarted> {
    type Capturing = SinspTestDriver<CaptureStarted>;
    type Plugin = SinspPlugin;

    const NAME: &'static str = "sinsp";

    fn new() -> anyhow::Result<Self> {
        let driver = ffi::new_test_driver();
        anyhow::ensure!(!driver.is_null(), "null driver");
        Ok(SinspTestDriver {
            driver,
            state: PhantomData,
        })
    }

    fn register_plugin(
        &mut self,
        api: &'static falco_plugin::api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<Self::Plugin> {
        let plugin = unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .register_plugin(api as *const _ as *const Api, config.as_ptr())?
        };
        Ok(SinspPlugin { plugin })
    }

    unsafe fn register_plugin_raw(
        &mut self,
        api: *const falco_plugin::api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<SinspPlugin> {
        let plugin = unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .register_plugin(api as *const _, config.as_ptr())?
        };
        Ok(SinspPlugin { plugin })
    }

    fn add_filterchecks(&mut self, plugin: &SinspPlugin, source: &CStr) -> anyhow::Result<()> {
        unsafe {
            Ok(self
                .driver
                .as_mut()
                .unwrap()
                .add_filterchecks(&plugin.plugin, source.as_ptr())?)
        }
    }

    fn start_capture(
        mut self,
        name: &CStr,
        config: &CStr,
        platform_data: PlatformData,
    ) -> anyhow::Result<Self::Capturing> {
        unsafe {
            self.driver.as_mut().unwrap().start_capture(
                name.as_ptr(),
                config.as_ptr(),
                platform_data == PlatformData::Enabled,
            )?;
        }

        Ok(SinspTestDriver::<CaptureStarted> {
            driver: self.driver,
            state: PhantomData,
        })
    }
}

impl SavefileTestDriver for SinspTestDriver<CaptureNotStarted> {
    fn load_capture_file(mut self, path: &CStr) -> anyhow::Result<SinspTestDriver<CaptureStarted>> {
        unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .load_capture_file(path.as_ptr())?;
        }

        Ok(SinspTestDriver::<CaptureStarted> {
            driver: self.driver,
            state: PhantomData,
        })
    }
}

impl CapturingTestDriver for SinspTestDriver<CaptureStarted> {
    type NonCapturing = SinspTestDriver<CaptureNotStarted>;
    type Event = SinspEvent;

    fn next_event(&mut self) -> Result<Self::Event, ScapStatus> {
        let event = self.driver.as_mut().unwrap().next();
        match event.rc {
            0 => Ok(SinspEvent { event }),
            1 => Err(ScapStatus::Failure),
            -1 => Err(ScapStatus::Timeout),
            6 => Err(ScapStatus::Eof),
            9 => Err(ScapStatus::NotSupported),
            e => Err(ScapStatus::Other(e)),
        }
    }

    fn event_field_as_string(
        &mut self,
        field_name: &CStr,
        event: &Self::Event,
    ) -> anyhow::Result<Option<String>> {
        let event_str = unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .event_field_as_string(field_name.as_ptr(), &event.event)?
        };

        if event_str.is_null() {
            Ok(None)
        } else {
            Ok(Some(event_str.to_string_lossy().to_string()))
        }
    }

    fn event_field_as_string_with_range(
        &mut self,
        field_name: &CStr,
        event: &Self::Event,
    ) -> anyhow::Result<Option<(String, Range<usize>)>> {
        let mut start = 1u32;
        let mut length = u32::MAX;

        let event_str = unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .event_field_as_string_with_offsets(
                    field_name.as_ptr(),
                    &event.event,
                    &mut start,
                    &mut length,
                )?
        };

        if event_str.is_null() {
            Ok(None)
        } else {
            Ok(Some((
                event_str.to_string_lossy().to_string(),
                start as usize..(start.wrapping_add(length)) as usize,
            )))
        }
    }

    // `sinsp` does not distinguish between a failed extraction and a successful one
    // that does not return any data. Our wrapper (c++/sinsp_test_driver.cpp) then considers
    // "no result" from sinsp an error, so we treat that error as an indicator of extracting
    // a None value.
    fn event_field_is_none(&mut self, field_name: &CStr, event: &Self::Event) -> bool {
        unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .event_field_as_string(field_name.as_ptr(), &event.event)
                .is_err()
        }
    }

    fn extract_field(
        &mut self,
        field_name: &CStr,
        event: &Self::Event,
    ) -> anyhow::Result<Option<ExtractedField>> {
        let extracted = unsafe {
            self.driver
                .as_mut()
                .unwrap()
                .extract_event_field(field_name.as_ptr(), &event.event)?
        };

        fn extract_one(
            field_type: ffi::ExtractFieldType,
            value: &RawExtractedValue,
        ) -> anyhow::Result<ExtractedField> {
            if value.ptr.is_null() {
                return Ok(ExtractedField::None);
            }

            fn extract_ipaddr(value: &RawExtractedValue) -> anyhow::Result<IpAddr> {
                match value.len {
                    4 => {
                        let bytes: [u8; 4] = unsafe { read_unaligned(value.ptr.cast()) };
                        let v = u32::from_be_bytes(bytes);
                        Ok(IpAddr::V4(Ipv4Addr::from(v)))
                    }
                    16 => {
                        let v: [u8; 16] = unsafe { read_unaligned(value.ptr.cast()) };
                        Ok(IpAddr::V6(Ipv6Addr::from(v)))
                    }
                    _ => anyhow::bail!("Invalid length for IP address: {}", value.len),
                }
            }

            match field_type {
                ffi::ExtractFieldType::Uint64 => {
                    let v = unsafe { std::ptr::read_unaligned(value.ptr.cast()) };
                    Ok(ExtractedField::U64(v))
                }
                ffi::ExtractFieldType::Bool => {
                    let v: u32 = unsafe { read_unaligned(value.ptr.cast()) };
                    Ok(ExtractedField::Bool(v != 0))
                }
                ffi::ExtractFieldType::RelTime => {
                    let v: u64 = unsafe { read_unaligned(value.ptr.cast()) };
                    Ok(ExtractedField::RelTime(std::time::Duration::from_nanos(v)))
                }
                ffi::ExtractFieldType::AbsTime => {
                    let v: u64 = unsafe { read_unaligned(value.ptr.cast()) };
                    Ok(ExtractedField::AbsTime(
                        std::time::UNIX_EPOCH + std::time::Duration::from_nanos(v),
                    ))
                }
                ffi::ExtractFieldType::String => {
                    let s = unsafe { CStr::from_ptr(value.ptr.cast()) };
                    Ok(ExtractedField::String(s.to_owned()))
                }
                ffi::ExtractFieldType::IpAddr => {
                    let ip = extract_ipaddr(value)?;
                    Ok(ExtractedField::IpAddr(ip))
                }
                ffi::ExtractFieldType::IpNet => {
                    let ip = extract_ipaddr(value)?;
                    Ok(ExtractedField::IpNet(PT_IPNET(ip)))
                }
                other => anyhow::bail!("Invalid field type: {:?}", other),
            }
        }

        if extracted.values.is_empty() {
            Ok(None)
        } else if extracted.is_list {
            let mut out = Vec::new();
            for value in extracted.values.iter() {
                out.push(extract_one(extracted.field_type, value)?);
            }
            Ok(Some(ExtractedField::Vec(out)))
        } else {
            let value = extracted.values.get(0).unwrap();
            extract_one(extracted.field_type, value).map(Some)
        }
    }

    fn get_metrics(&mut self) -> anyhow::Result<Vec<SinspMetric>> {
        let mut out = Vec::new();
        let metrics = self.driver.as_mut().unwrap().get_metrics()?;

        anyhow::ensure!(!metrics.is_null(), "null metrics");
        for metric in metrics.as_ref().unwrap() {
            anyhow::ensure!(!metric.name.is_null(), "null metric name");
            let name = metric.name.as_ref().unwrap().to_string_lossy().to_string();
            let value = metric.value;

            out.push(SinspMetric { name, value });
        }

        Ok(out)
    }
}

pub type Driver = SinspTestDriver<CaptureNotStarted>;
