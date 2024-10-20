use crate::plugin::base::PluginWrapper;
use crate::plugin::error::ffi_result::FfiResult;
use crate::plugin::source::SourcePluginInstanceWrapper;
use crate::source::{EventBatch, EventInput, SourcePlugin, SourcePluginInstance};
use crate::strings::cstring_writer::WriteIntoCString;
use crate::strings::from_ptr::try_str_from_ptr;
use falco_plugin_api::plugin_api__bindgen_ty_1 as source_plugin_api;
use falco_plugin_api::{
    ss_instance_t, ss_plugin_event, ss_plugin_event_input, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_t,
};
use std::ffi::c_char;
use std::io::Write;

/// Marker trait to mark a source plugin as exported to the API
///
/// # Safety
///
/// Only implement this trait if you export the plugin either statically or dynamically
/// to the plugin API. This is handled by the `source_plugin!` and `static_plugin!` macros, so you
/// should never need to implement this trait manually.
#[diagnostic::on_unimplemented(
    message = "Source plugin is not exported",
    note = "use either `source_plugin!` or `static_plugin!`"
)]
pub unsafe trait SourcePluginExported {}

pub trait SourcePluginFallbackApi {
    const SOURCE_API: source_plugin_api = source_plugin_api {
        get_id: None,
        get_event_source: None,
        open: None,
        close: None,
        list_open_params: None,
        get_progress: None,
        event_to_string: None,
        next_batch: None,
    };
}
impl<T> SourcePluginFallbackApi for T {}

#[allow(missing_debug_implementations)]
pub struct SourcePluginApi<T>(std::marker::PhantomData<T>);

impl<T: SourcePlugin> SourcePluginApi<T> {
    pub const SOURCE_API: source_plugin_api = source_plugin_api {
        get_id: Some(plugin_get_id::<T>),
        get_event_source: Some(plugin_get_event_source::<T>),
        open: Some(plugin_open::<T>),
        close: Some(plugin_close::<T>),
        list_open_params: Some(plugin_list_open_params::<T>),
        get_progress: Some(plugin_get_progress::<T>),
        event_to_string: Some(plugin_event_to_string::<T>),
        next_batch: Some(plugin_next_batch::<T>),
    };
}

pub extern "C-unwind" fn plugin_get_event_source<T: SourcePlugin>() -> *const c_char {
    T::EVENT_SOURCE.as_ptr()
}

pub extern "C-unwind" fn plugin_get_id<T: SourcePlugin>() -> u32 {
    T::PLUGIN_ID
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_list_open_params<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    rc: *mut i32,
) -> *const c_char {
    let plugin = plugin as *mut PluginWrapper<T>;
    let Some(plugin) = plugin.as_mut() else {
        return std::ptr::null();
    };
    let Some(ref mut actual_plugin) = &mut plugin.plugin else {
        return std::ptr::null();
    };

    match actual_plugin.plugin.list_open_params() {
        Ok(s) => {
            unsafe {
                *rc = ss_plugin_rc_SS_PLUGIN_SUCCESS;
            }
            s.as_ptr()
        }
        Err(e) => {
            unsafe {
                *rc = e.status_code();
            }
            e.set_last_error(&mut plugin.error_buf);
            std::ptr::null()
        }
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_open<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    params: *const c_char,
    rc: *mut ss_plugin_rc,
) -> *mut ss_instance_t {
    let plugin = plugin as *mut PluginWrapper<T>;
    unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return std::ptr::null_mut();
        };
        let Some(ref mut actual_plugin) = &mut plugin.plugin else {
            return std::ptr::null_mut();
        };

        let Some(rc) = rc.as_mut() else {
            return std::ptr::null_mut();
        };

        let params = if params.is_null() {
            None
        } else {
            match try_str_from_ptr(&params) {
                Ok(params) => Some(params),
                Err(e) => {
                    plugin
                        .error_buf
                        .write_into(|w| w.write_all(e.to_string().as_bytes()))
                        .ok();
                    *rc = ss_plugin_rc_SS_PLUGIN_FAILURE;

                    return std::ptr::null_mut();
                }
            }
        };

        match actual_plugin.plugin.open(params) {
            Ok(instance) => {
                *rc = ss_plugin_rc_SS_PLUGIN_SUCCESS;
                Box::into_raw(Box::new(SourcePluginInstanceWrapper {
                    instance,
                    batch: Default::default(),
                }))
                .cast()
            }
            Err(e) => {
                e.set_last_error(&mut plugin.error_buf);
                *rc = e.status_code();
                std::ptr::null_mut()
            }
        }
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_close<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    instance: *mut ss_instance_t,
) {
    let plugin = plugin as *mut PluginWrapper<T>;
    let Some(plugin) = plugin.as_mut() else {
        return;
    };
    let Some(ref mut actual_plugin) = &mut plugin.plugin else {
        return;
    };

    let instance = instance as *mut SourcePluginInstanceWrapper<T::Instance>;
    unsafe {
        let mut inst = Box::from_raw(instance);
        actual_plugin.plugin.close(&mut inst.instance);
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_next_batch<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    instance: *mut ss_instance_t,
    nevts: *mut u32,
    evts: *mut *mut *mut ss_plugin_event,
) -> ss_plugin_rc {
    let plugin = plugin as *mut PluginWrapper<T>;
    let instance = instance as *mut SourcePluginInstanceWrapper<T::Instance>;
    unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(ref mut actual_plugin) = &mut plugin.plugin else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let Some(instance) = instance.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        instance.batch.reset();
        let mut batch = EventBatch::new(&mut instance.batch);
        match instance
            .instance
            .next_batch(&mut actual_plugin.plugin, &mut batch)
        {
            Ok(()) => {
                let events = batch.get_events();
                *nevts = events.len() as u32;
                *evts = events as *const _ as *mut _;
                ss_plugin_rc_SS_PLUGIN_SUCCESS
            }
            Err(e) => {
                *nevts = 0;
                *evts = std::ptr::null_mut();
                e.set_last_error(&mut plugin.error_buf);
                e.status_code()
            }
        }
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_get_progress<T: SourcePlugin>(
    _plugin: *mut ss_plugin_t,
    instance: *mut ss_instance_t,
    progress_pct: *mut u32,
) -> *const c_char {
    let instance = instance as *mut SourcePluginInstanceWrapper<T::Instance>;
    let progress = unsafe { instance.as_mut() }.map(|instance| instance.instance.get_progress());

    if let Some(progress) = progress {
        unsafe {
            *progress_pct = (progress.value * 100.0) as u32;
        }

        match progress.detail {
            Some(s) => s.as_ptr(),
            None => std::ptr::null(),
        }
    } else {
        unsafe {
            *progress_pct = 0;
        }

        std::ptr::null()
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_event_to_string<T: SourcePlugin>(
    plugin: *mut ss_plugin_t,
    event: *const ss_plugin_event_input,
) -> *const c_char {
    let plugin = plugin as *mut PluginWrapper<T>;
    unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return std::ptr::null();
        };
        let Some(ref mut actual_plugin) = &mut plugin.plugin else {
            return std::ptr::null();
        };

        let Some(event) = event.as_ref() else {
            return std::ptr::null();
        };
        let event = EventInput(*event);

        match actual_plugin.plugin.event_to_string(&event) {
            Ok(s) => {
                plugin.string_storage = s;
                plugin.string_storage.as_ptr()
            }
            Err(_) => std::ptr::null(),
        }
    }
}

/// # Register a source plugin
///
/// This macro must be called at most once in a crate (it generates public functions with fixed
/// `#[no_mangle]` names) with a type implementing [`SourcePlugin`] as the sole parameter.
#[macro_export]
macro_rules! source_plugin {
    ($ty:ty) => {
        unsafe impl $crate::internals::source::wrappers::SourcePluginExported for $ty {}

        $crate::wrap_ffi! {
            #[no_mangle]
            use $crate::internals::source::wrappers: <$ty>;
            unsafe fn plugin_next_batch(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                instance: *mut falco_plugin::api::ss_instance_t,
                nevts: *mut u32,
                evts: *mut *mut *mut falco_plugin::api::ss_plugin_event,
            ) -> i32;
            unsafe fn plugin_get_progress(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                instance: *mut falco_plugin::api::ss_instance_t,
                progress_pct: *mut u32,
            ) -> *const ::std::ffi::c_char;
            unsafe fn plugin_get_id() -> u32;
            unsafe fn plugin_get_event_source() -> *const ::std::ffi::c_char;
            unsafe fn plugin_list_open_params(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                rc: *mut i32,
            ) -> *const ::std::ffi::c_char;
            unsafe fn plugin_open(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                params: *const ::std::ffi::c_char,
                rc: *mut i32,
            ) -> *mut falco_plugin::api::ss_instance_t;
            unsafe fn plugin_close(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                instance: *mut falco_plugin::api::ss_instance_t,
            ) -> ();
            unsafe fn plugin_event_to_string(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                event_input: *const falco_plugin::api::ss_plugin_event_input,
            ) -> *const std::ffi::c_char;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_source_api() -> falco_plugin::api::plugin_api__bindgen_ty_1 {
            falco_plugin::api::plugin_api__bindgen_ty_1 {
                next_batch: Some(plugin_next_batch),
                get_progress: Some(plugin_get_progress),
                get_id: Some(plugin_get_id),
                get_event_source: Some(plugin_get_event_source),
                list_open_params: Some(plugin_list_open_params),
                open: Some(plugin_open),
                close: Some(plugin_close),
                event_to_string: Some(plugin_event_to_string),
            }
        }
    };
}
