use crate::plugin::async_event::async_handler::AsyncHandler;
use crate::plugin::async_event::AsyncEventPlugin;
use crate::plugin::base::PluginWrapper;
use crate::plugin::error::ffi_result::FfiResult;
use falco_plugin_api::plugin_api__bindgen_ty_4 as async_plugin_api;
use falco_plugin_api::{
    ss_plugin_async_event_handler_t, ss_plugin_owner_t, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_t,
};
use std::any::TypeId;
use std::collections::BTreeMap;
use std::ffi::{c_char, CString};
use std::sync::Mutex;

/// Marker trait to mark an async plugin as exported to the API
///
/// # Safety
///
/// Only implement this trait if you export the plugin either statically or dynamically
/// to the plugin API. This is handled by the `async_plugin!` and `static_plugin!` macros, so you
/// should never need to implement this trait manually.
#[diagnostic::on_unimplemented(
    message = "Async plugin is not exported",
    note = "use either `async_plugin!` or `static_plugin!`"
)]
pub unsafe trait AsyncPluginExported {}

pub trait AsyncPluginFallbackApi {
    const ASYNC_API: async_plugin_api = async_plugin_api {
        get_async_event_sources: None,
        get_async_events: None,
        set_async_event_handler: None,
        dump_state: None,
    };

    const IMPLEMENTS_ASYNC: bool = false;
}
impl<T> AsyncPluginFallbackApi for T {}

#[derive(Debug)]
pub struct AsyncPluginApi<T>(std::marker::PhantomData<T>);
impl<T: AsyncEventPlugin + 'static> AsyncPluginApi<T> {
    pub const ASYNC_API: async_plugin_api = async_plugin_api {
        get_async_event_sources: Some(plugin_get_async_event_sources::<T>),
        get_async_events: Some(plugin_get_async_events::<T>),
        set_async_event_handler: Some(plugin_set_async_event_handler::<T>),
        dump_state: Some(plugin_dump_state::<T>),
    };

    pub const IMPLEMENTS_ASYNC: bool = true;
}

pub extern "C-unwind" fn plugin_get_async_event_sources<T: AsyncEventPlugin + 'static>(
) -> *const c_char {
    static SOURCES: Mutex<BTreeMap<TypeId, CString>> = Mutex::new(BTreeMap::new());

    let ty = TypeId::of::<T>();
    let mut sources_map = SOURCES.lock().unwrap();
    // we only generate the string once and never change or delete it
    // so the pointer should remain valid for the static lifetime
    sources_map
        .entry(ty)
        .or_insert_with(|| {
            let sources = serde_json::to_string(T::EVENT_SOURCES)
                .expect("failed to serialize event source array");
            CString::new(sources.into_bytes()).expect("failed to add NUL to event source array")
        })
        .as_ptr()
}

pub extern "C-unwind" fn plugin_get_async_events<T: AsyncEventPlugin + 'static>() -> *const c_char {
    static EVENTS: Mutex<BTreeMap<TypeId, CString>> = Mutex::new(BTreeMap::new());

    let ty = TypeId::of::<T>();
    let mut event_map = EVENTS.lock().unwrap();
    // we only generate the string once and never change or delete it
    // so the pointer should remain valid for the static lifetime
    event_map
        .entry(ty)
        .or_insert_with(|| {
            let sources = serde_json::to_string(T::ASYNC_EVENTS)
                .expect("failed to serialize event name array");
            CString::new(sources.into_bytes()).expect("failed to add NUL to event name array")
        })
        .as_ptr()
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_set_async_event_handler<T: AsyncEventPlugin>(
    plugin: *mut ss_plugin_t,
    owner: *mut ss_plugin_owner_t,
    handler: ss_plugin_async_event_handler_t,
) -> ss_plugin_rc {
    unsafe {
        let Some(plugin) = (plugin as *mut PluginWrapper<T>).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let Some(ref mut actual_plugin) = &mut plugin.plugin else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        if let Err(e) = actual_plugin.plugin.stop_async() {
            e.set_last_error(&mut plugin.error_buf);
            return e.status_code();
        }

        let Some(raw_handler) = handler.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_SUCCESS;
        };

        let handler = AsyncHandler {
            owner,
            raw_handler: *raw_handler,
        };
        if let Err(e) = actual_plugin.plugin.start_async(handler) {
            e.set_last_error(&mut plugin.error_buf);
            return e.status_code();
        }

        ss_plugin_rc_SS_PLUGIN_SUCCESS
    }
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_dump_state<T: AsyncEventPlugin>(
    plugin: *mut ss_plugin_t,
    owner: *mut ss_plugin_owner_t,
    handler: ss_plugin_async_event_handler_t,
) -> ss_plugin_rc {
    unsafe {
        let Some(plugin) = (plugin as *mut PluginWrapper<T>).as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let Some(ref mut actual_plugin) = &mut plugin.plugin else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let Some(raw_handler) = handler.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_SUCCESS;
        };

        let handler = AsyncHandler {
            owner,
            raw_handler: *raw_handler,
        };
        if let Err(e) = actual_plugin.plugin.dump_state(handler) {
            e.set_last_error(&mut plugin.error_buf);
            return e.status_code();
        }

        ss_plugin_rc_SS_PLUGIN_SUCCESS
    }
}

/// # Register an asynchronous event plugin
///
/// This macro must be called at most once in a crate (it generates public functions with fixed
/// `#[no_mangle]` names) with a type implementing [`AsyncEventPlugin`] as the sole
/// parameter.
#[macro_export]
macro_rules! async_event_plugin {
    ($ty:ty) => {
        unsafe impl $crate::internals::async_event::wrappers::AsyncPluginExported for $ty {}

        $crate::wrap_ffi! {
            #[no_mangle]
            use $crate::internals::async_event::wrappers: <$ty>;

            unsafe fn plugin_get_async_events() -> *const ::std::ffi::c_char;
            unsafe fn plugin_get_async_event_sources() -> *const ::std::ffi::c_char;
            unsafe fn plugin_set_async_event_handler(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                owner: *mut falco_plugin::api::ss_plugin_owner_t,
                handler: falco_plugin::api::ss_plugin_async_event_handler_t,
            ) -> falco_plugin::api::ss_plugin_rc;
            unsafe fn plugin_dump_state(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                owner: *mut falco_plugin::api::ss_plugin_owner_t,
                handler: falco_plugin::api::ss_plugin_async_event_handler_t,
            ) -> falco_plugin::api::ss_plugin_rc;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_async_api() -> falco_plugin::api::plugin_api__bindgen_ty_4 {
            falco_plugin::api::plugin_api__bindgen_ty_4 {
                get_async_event_sources: Some(plugin_get_async_event_sources),
                get_async_events: Some(plugin_get_async_events),
                set_async_event_handler: Some(plugin_set_async_event_handler),
                dump_state: Some(plugin_dump_state),
            }
        }
    };
}
