use crate::listen::CaptureListenPlugin;
use crate::plugin::base::PluginWrapper;
use crate::plugin::error::ffi_result::FfiResult;
use crate::plugin::listen::CaptureListenInput;
use falco_plugin_api::{
    plugin_api__bindgen_ty_5 as listen_plugin_api, ss_plugin_capture_listen_input, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_t,
};

/// Marker trait to mark a capture listen plugin as exported to the API
///
/// # Safety
///
/// Only implement this trait if you export the plugin either statically or dynamically
/// to the plugin API. This is handled by the `capture_listen_plugin!` and `static_plugin!` macros, so you
/// should never need to implement this trait manually.
#[diagnostic::on_unimplemented(
    message = "Capture listen plugin is not exported",
    note = "use either `capture_listen_plugin!` or `static_plugin!`"
)]
pub unsafe trait CaptureListenPluginExported {}

pub trait CaptureListenFallbackApi {
    const LISTEN_API: listen_plugin_api = listen_plugin_api {
        capture_open: None,
        capture_close: None,
    };
}

impl<T> CaptureListenFallbackApi for T {}

#[derive(Debug)]
pub struct CaptureListenApi<T>(std::marker::PhantomData<T>);
impl<T: CaptureListenPlugin + 'static> CaptureListenApi<T> {
    pub const LISTEN_API: listen_plugin_api = listen_plugin_api {
        capture_open: Some(plugin_capture_open::<T>),
        capture_close: Some(plugin_capture_close::<T>),
    };
}

pub unsafe extern "C-unwind" fn plugin_capture_open<T: CaptureListenPlugin>(
    plugin: *mut ss_plugin_t,
    listen_input: *const ss_plugin_capture_listen_input,
) -> ss_plugin_rc {
    let Some(plugin) = (plugin as *mut PluginWrapper<T>).as_mut() else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    let Some(ref mut actual_plugin) = &mut plugin.plugin else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    let Ok(listen_input) =
        CaptureListenInput::try_from(listen_input, actual_plugin.last_error.clone())
    else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    if let Err(e) = actual_plugin.plugin.capture_open(&listen_input) {
        e.set_last_error(&mut plugin.error_buf);
        return e.status_code();
    }

    ss_plugin_rc_SS_PLUGIN_SUCCESS
}

pub unsafe extern "C-unwind" fn plugin_capture_close<T: CaptureListenPlugin>(
    plugin: *mut ss_plugin_t,
    listen_input: *const ss_plugin_capture_listen_input,
) -> ss_plugin_rc {
    let Some(plugin) = (plugin as *mut PluginWrapper<T>).as_mut() else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    let Some(ref mut actual_plugin) = &mut plugin.plugin else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    let Ok(listen_input) =
        CaptureListenInput::try_from(listen_input, actual_plugin.last_error.clone())
    else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    if let Err(e) = actual_plugin.plugin.capture_close(&listen_input) {
        e.set_last_error(&mut plugin.error_buf);
        return e.status_code();
    }

    ss_plugin_rc_SS_PLUGIN_SUCCESS
}

/// # Register an asynchronous event plugin
///
/// This macro must be called at most once in a crate (it generates public functions with fixed
/// `#[no_mangle]` names) with a type implementing [`CaptureListenPlugin`] as the sole
/// parameter.
#[macro_export]
macro_rules! capture_listen_plugin {
    ($ty:ty) => {
        unsafe impl $crate::internals::listen::wrappers::CaptureListenPluginExported for $ty {}

        $crate::wrap_ffi! {
            #[no_mangle]
            use $crate::internals::listen::wrappers: <$ty>;

            unsafe fn plugin_capture_open(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                listen_input: *const falco_plugin::api::ss_plugin_capture_listen_input,
            ) -> falco_plugin::api::ss_plugin_rc;
            unsafe fn plugin_capture_close(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                listen_input: *const falco_plugin::api::ss_plugin_capture_listen_input,
            ) -> falco_plugin::api::ss_plugin_rc;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_listen_api() -> falco_plugin::api::plugin_api__bindgen_ty_5 {
            falco_plugin::api::plugin_api__bindgen_ty_5 {
                capture_open: Some(plugin_capture_open),
                capture_close: Some(plugin_capture_close),
            }
        }
    };
}
