use crate::base::Plugin;
use crate::plugin::base::logger::{FalcoPluginLoggerImpl, FALCO_LOGGER};
use crate::plugin::base::PluginWrapper;
use crate::plugin::error::ffi_result::FfiResult;
use crate::plugin::error::last_error::LastError;
use crate::plugin::schema::{ConfigSchema, ConfigSchemaType};
use crate::plugin::tables::vtable::TablesInput;
use crate::strings::from_ptr::try_str_from_ptr;
use anyhow::Context;
use falco_plugin_api::{
    ss_plugin_init_input, ss_plugin_metric, ss_plugin_rc, ss_plugin_rc_SS_PLUGIN_FAILURE,
    ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_t,
};
use std::collections::BTreeMap;
use std::ffi::{c_char, CString};
use std::sync::Mutex;

/// Marker trait to mark a plugin as exported to the API
///
/// # Safety
///
/// Only implement this trait if you export the plugin either statically or dynamically
/// to the plugin API. This is handled by the `plugin!` and `static_plugin!` macros, so you
/// should never need to implement this trait manually.
#[diagnostic::on_unimplemented(
    message = "Plugin is not exported",
    note = "use either `plugin!` or `static_plugin!`"
)]
pub unsafe trait BasePluginExported {}

pub extern "C-unwind" fn plugin_get_required_api_version<
    const MAJOR: usize,
    const MINOR: usize,
    const PATCH: usize,
>() -> *const c_char {
    static VERSIONS: Mutex<BTreeMap<(usize, usize, usize), CString>> = Mutex::new(BTreeMap::new());

    let mut version = VERSIONS.lock().unwrap();
    // we only generate the string once and never change or delete it
    // so the pointer should remain valid for the static lifetime
    version
        .entry((MAJOR, MINOR, PATCH))
        .or_insert_with(|| {
            let version = format!("{MAJOR}.{MINOR}.{PATCH}");
            CString::new(version).unwrap()
        })
        .as_ptr()
}

pub extern "C-unwind" fn plugin_get_version<T: Plugin>() -> *const c_char {
    T::PLUGIN_VERSION.as_ptr()
}

pub extern "C-unwind" fn plugin_get_name<T: Plugin>() -> *const c_char {
    T::NAME.as_ptr()
}

pub extern "C-unwind" fn plugin_get_description<T: Plugin>() -> *const c_char {
    T::DESCRIPTION.as_ptr()
}

pub extern "C-unwind" fn plugin_get_contact<T: Plugin>() -> *const c_char {
    T::CONTACT.as_ptr()
}

/// # Safety
///
/// init_input must be null or a valid pointer
pub unsafe extern "C-unwind" fn plugin_init<P: Plugin>(
    init_input: *const ss_plugin_init_input,
    rc: *mut ss_plugin_rc,
) -> *mut falco_plugin_api::ss_plugin_t {
    let res = (|| -> Result<*mut PluginWrapper<P>, anyhow::Error> {
        let init_input = unsafe { init_input.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("Got empty init_input"))?;

        let init_config =
            try_str_from_ptr(&init_input.config).context("Failed to get config string")?;

        let config = P::ConfigType::from_str(init_config).context("Failed to parse config")?;
        if let Some(log_fn) = init_input.log_fn {
            let logger_impl = FalcoPluginLoggerImpl {
                owner: init_input.owner,
                logger_fn: log_fn,
            };

            *FALCO_LOGGER.inner.write().unwrap() = Some(logger_impl);
            log::set_logger(&FALCO_LOGGER).ok();

            #[cfg(debug_assertions)]
            log::set_max_level(log::LevelFilter::Trace);

            #[cfg(not(debug_assertions))]
            log::set_max_level(log::LevelFilter::Info);
        }

        let tables_input =
            TablesInput::try_from(init_input).context("Failed to build tables input")?;

        let last_error = unsafe { LastError::from(init_input)? };

        P::new(tables_input.as_ref(), config)
            .map(|plugin| Box::into_raw(Box::new(PluginWrapper::new(plugin, last_error))))
    })();

    match res {
        Ok(plugin) => {
            unsafe {
                *rc = ss_plugin_rc_SS_PLUGIN_SUCCESS;
            }
            plugin.cast()
        }
        Err(e) => {
            let error_str = format!("{:#}", &e);
            log::error!("Failed to initialize plugin: {error_str}");
            let plugin = Box::new(PluginWrapper::<P>::new_error(error_str));
            unsafe {
                *rc = e.status_code();
            }
            Box::into_raw(plugin).cast()
        }
    }
}

/// # Safety
///
/// schema_type must be null or a valid pointer
pub unsafe extern "C-unwind" fn plugin_get_init_schema<P: Plugin>(
    schema_type: *mut falco_plugin_api::ss_plugin_schema_type,
) -> *const c_char {
    let schema_type = unsafe {
        let Some(schema_type) = schema_type.as_mut() else {
            return std::ptr::null();
        };
        schema_type
    };
    match P::ConfigType::get_schema() {
        ConfigSchemaType::None => {
            *schema_type = falco_plugin_api::ss_plugin_schema_type_SS_PLUGIN_SCHEMA_NONE;
            std::ptr::null()
        }
        ConfigSchemaType::Json(s) => {
            *schema_type = falco_plugin_api::ss_plugin_schema_type_SS_PLUGIN_SCHEMA_JSON;
            s.as_ptr()
        }
    }
}

/// # Safety
///
/// `plugin` must have been created by `init()` and not destroyed since
pub unsafe extern "C-unwind" fn plugin_destroy<P: Plugin>(
    plugin: *mut falco_plugin_api::ss_plugin_t,
) {
    unsafe {
        let plugin = plugin as *mut PluginWrapper<P>;
        let _ = Box::from_raw(plugin);
    }
}

/// # Safety
///
/// `plugin` must be a valid pointer to `PluginWrapper<P>`
pub unsafe extern "C-unwind" fn plugin_get_last_error<P: Plugin>(
    plugin: *mut falco_plugin_api::ss_plugin_t,
) -> *const c_char {
    let plugin = plugin as *mut PluginWrapper<P>;
    match unsafe { plugin.as_mut() } {
        Some(plugin) => plugin.error_buf.as_ptr(),
        None => c"no instance".as_ptr(),
    }
}

pub unsafe extern "C-unwind" fn plugin_set_config<P: Plugin>(
    plugin: *mut falco_plugin_api::ss_plugin_t,
    config_input: *const falco_plugin_api::ss_plugin_set_config_input,
) -> falco_plugin_api::ss_plugin_rc {
    let plugin = plugin as *mut PluginWrapper<P>;
    let plugin = unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        plugin
    };

    let Some(actual_plugin) = &mut plugin.plugin else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    let res = (|| -> Result<(), anyhow::Error> {
        let config_input = unsafe { config_input.as_ref() }.context("Got NULL config")?;

        let updated_config =
            try_str_from_ptr(&config_input.config).context("Failed to get config string")?;
        let config = P::ConfigType::from_str(updated_config).context("Failed to parse config")?;

        actual_plugin.plugin.set_config(config)
    })();

    res.rc(&mut plugin.error_buf)
}

pub unsafe extern "C-unwind" fn plugin_get_metrics<P: Plugin>(
    plugin: *mut ss_plugin_t,
    num_metrics: *mut u32,
) -> *mut ss_plugin_metric {
    let plugin = plugin as *mut PluginWrapper<P>;
    let num_metrics = unsafe {
        let Some(num_metrics) = num_metrics.as_mut() else {
            return std::ptr::null_mut();
        };
        num_metrics
    };

    let plugin = unsafe {
        let Some(plugin) = plugin.as_mut() else {
            *num_metrics = 0;
            return std::ptr::null_mut();
        };
        plugin
    };

    let Some(actual_plugin) = &mut plugin.plugin else {
        *num_metrics = 0;
        return std::ptr::null_mut();
    };

    plugin.metric_storage.clear();
    for metric in actual_plugin.plugin.get_metrics() {
        plugin.metric_storage.push(metric.as_raw());
    }

    *num_metrics = plugin.metric_storage.len() as u32;
    plugin.metric_storage.as_ptr().cast_mut()
}

#[doc(hidden)]
#[macro_export]
macro_rules! wrap_ffi {
    (
        #[$attr:meta]
        use $mod:path: <$ty:ty>;

    $(unsafe fn $name:ident( $($param:ident: $param_ty:ty),* $(,)*) -> $ret:ty;)*
    ) => {
        $(
        #[$attr]
        pub unsafe extern "C-unwind" fn $name ( $($param: $param_ty),*) -> $ret {
            use $mod as wrappers;

            wrappers::$name::<$ty>($($param),*)
        }
        )*
    }
}

/// # Register a Falco plugin
///
/// This macro must be called at most once in a crate (it generates public functions)
/// with a type implementing [`Plugin`] as the sole parameter:
///
/// ```
/// # use std::ffi::CStr;
/// use falco_plugin::base::Plugin;
/// # use falco_plugin::base::Metric;
/// use falco_plugin::plugin;
/// use falco_plugin::tables::TablesInput;
///
/// struct MyPlugin;
/// impl Plugin for MyPlugin {
///     // ...
/// #    const NAME: &'static CStr = c"sample-plugin-rs";
/// #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
/// #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
/// #    const CONTACT: &'static CStr = c"you@example.com";
/// #    type ConfigType = ();
/// #
/// #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
/// #        -> Result<Self, anyhow::Error> {
/// #        Ok(MyPlugin)
/// #    }
/// #
/// #    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
/// #        Ok(())
/// #    }
/// #
/// #    fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
/// #        []
/// #    }
/// }
///
/// plugin!(#[no_capabilities] MyPlugin);
/// ```
///
/// It implements a form where you can override the required API version (for example, if
/// you wish to advertise an older version for increased compatibility):
///
/// ```
/// # use std::ffi::CStr;
/// use falco_plugin::base::Plugin;
/// # use falco_plugin::base::Metric;
/// use falco_plugin::plugin;
/// use falco_plugin::tables::TablesInput;
///
/// struct MyPlugin;
/// impl Plugin for MyPlugin {
///     // ...
/// #    const NAME: &'static CStr = c"sample-plugin-rs";
/// #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
/// #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
/// #    const CONTACT: &'static CStr = c"you@example.com";
/// #    type ConfigType = ();
/// #
/// #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
/// #        -> Result<Self, anyhow::Error> {
/// #        Ok(MyPlugin)
/// #    }
/// #
/// #    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
/// #        Ok(())
/// #    }
/// #
/// #    fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
/// #        []
/// #    }
/// }
///
/// // require version 3.3.0 of the API
/// plugin!(unsafe { 3;3;0 } => #[no_capabilities] MyPlugin);
/// ```
///
/// **Note**: this does not affect the actual version supported in any way. If you use this form,
/// it's **entirely your responsibility** to ensure the advertised version is compatible with the actual
/// version supported by this crate.
#[macro_export]
macro_rules! plugin {
    (unsafe { $maj:expr; $min:expr; $patch:expr } => #[no_capabilities] $ty:ty) => {
        unsafe impl $crate::internals::base::wrappers::BasePluginExported for $ty {}

        $crate::base_plugin_ffi_wrappers!($maj; $min; $patch => #[unsafe(no_mangle)] $ty);
    };
    (unsafe { $maj:expr; $min:expr; $patch:expr } => $ty:ty) => {
        plugin!(unsafe {$maj; $min; $patch} => #[no_capabilities] $ty);

        $crate::ensure_plugin_capabilities!($ty);
    };
    ($(#[$attr:tt])? $ty:ty) => {
        plugin!(
            unsafe {
                falco_plugin::api::PLUGIN_API_VERSION_MAJOR as usize;
                falco_plugin::api::PLUGIN_API_VERSION_MINOR as usize;
                0
            } => $(#[$attr])? $ty
        );
    };
}

/// # Automatically generate the Falco plugin API structure for static plugins
///
/// This macro generates a [`falco_plugin_api::plugin_api`] structure, usable as a statically
/// linked plugin. It automatically handles all supported capabilities, so you need just one
/// invocation, regardless of how many capabilities your plugin supports.
///
/// ## Basic usage
///
/// ```
///# use std::ffi::CStr;
///# use falco_plugin::base::Metric;
/// use falco_plugin::base::Plugin;
/// use falco_plugin::static_plugin;
///# use falco_plugin::tables::TablesInput;
///
///# struct MyPlugin;
///#
/// impl Plugin for MyPlugin {
///     // ...
///#     const NAME: &'static CStr = c"sample-plugin-rs";
///#     const PLUGIN_VERSION: &'static CStr = c"0.0.1";
///#     const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
///#     const CONTACT: &'static CStr = c"you@example.com";
///#     type ConfigType = ();
///#
///#     fn new(input: Option<&TablesInput>, config: Self::ConfigType)
///#         -> Result<Self, anyhow::Error> {
///#         Ok(MyPlugin)
///#     }
///#
///#     fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
///#         Ok(())
///#     }
///#
///#     fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
///#         []
///#     }
/// }
///
/// static_plugin!(#[no_capabilities] MY_PLUGIN_API = MyPlugin);
/// ```
///
/// This expands to:
/// ```ignore
/// #[unsafe(no_mangle)]
/// static MY_PLUGIN_API: falco_plugin::api::plugin_api = /* ... */;
/// ```
///
/// The symbols referred to in the API structure are still mangled according to default Rust rules.
///
/// ## Overriding the supported API version
///
/// The macro also implements a form where you can override the required API version (for example,
/// if you wish to advertise an older version for increased compatibility):
///
/// ```
///# use std::ffi::CStr;
///# use falco_plugin::base::Metric;
/// use falco_plugin::base::Plugin;
/// use falco_plugin::static_plugin;
///# use falco_plugin::tables::TablesInput;
///
///# struct MyPlugin;
///#
/// impl Plugin for MyPlugin {
///     // ...
///#     const NAME: &'static CStr = c"sample-plugin-rs";
///#     const PLUGIN_VERSION: &'static CStr = c"0.0.1";
///#     const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
///#     const CONTACT: &'static CStr = c"you@example.com";
///#     type ConfigType = ();
///#
///#     fn new(input: Option<&TablesInput>, config: Self::ConfigType)
///#         -> Result<Self, anyhow::Error> {
///#         Ok(MyPlugin)
///#     }
///#
///#     fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
///#         Ok(())
///#     }
///#
///#     fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
///#         []
///#     }
/// }
///
/// // advertise API version 3.3.0
/// static_plugin!(MY_PLUGIN_API @ unsafe { 3;3;0 } = #[no_capabilities] MyPlugin);
/// ```
///
/// **Note**: this does not affect the actual version supported in any way. If you use this form,
/// it's **entirely your responsibility** to ensure the advertised version is compatible with the actual
/// version supported by this crate.
#[macro_export]
macro_rules! static_plugin {
    ($(#[$attr:tt])? $vis:vis $name:ident = $ty:ty) => {
        static_plugin!(
            $vis $name @ unsafe {
                falco_plugin::api::PLUGIN_API_VERSION_MAJOR as usize;
                falco_plugin::api::PLUGIN_API_VERSION_MINOR as usize;
                0
            }
            = $(#[$attr])? $ty
        );
    };
    ($vis:vis $name:ident @ unsafe { $maj:expr; $min:expr; $patch:expr } = #[no_capabilities] $ty:ty) => {
        #[unsafe(no_mangle)]
        $vis static $name: falco_plugin::api::plugin_api = const {
            $crate::base_plugin_ffi_wrappers!($maj; $min; $patch => #[deny(dead_code)] $ty);
            __plugin_base_api()
        };

        // a static plugin automatically exports all capabilities
        unsafe impl $crate::internals::base::wrappers::BasePluginExported for $ty {}
        unsafe impl $crate::internals::async_event::wrappers::AsyncPluginExported for $ty {}
        unsafe impl $crate::internals::extract::wrappers::ExtractPluginExported for $ty {}
        unsafe impl $crate::internals::listen::wrappers::CaptureListenPluginExported for $ty {}
        unsafe impl $crate::internals::parse::wrappers::ParsePluginExported for $ty {}
        unsafe impl $crate::internals::source::wrappers::SourcePluginExported for $ty {}
    };
    ($vis:vis $name:ident @ unsafe { $maj:expr; $min:expr; $patch:expr } = $ty:ty) => {
        static_plugin!($vis $name @ unsafe { $maj; $min; $patch } = #[no_capabilities] $ty);

        $crate::ensure_plugin_capabilities!($ty);
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! ensure_plugin_capabilities {
    ($ty:ty) => {
        const _: () = {
            use $crate::internals::async_event::wrappers::AsyncPluginFallbackApi;
            use $crate::internals::extract::wrappers::ExtractPluginFallbackApi;
            use $crate::internals::listen::wrappers::CaptureListenFallbackApi;
            use $crate::internals::parse::wrappers::ParsePluginFallbackApi;
            use $crate::internals::source::wrappers::SourcePluginFallbackApi;

            let impls_async =
                $crate::internals::async_event::wrappers::AsyncPluginApi::<$ty>::IMPLEMENTS_ASYNC;
            let impls_extract =
                $crate::internals::extract::wrappers::ExtractPluginApi::<$ty>::IMPLEMENTS_EXTRACT;
            let impls_listen =
                $crate::internals::listen::wrappers::CaptureListenApi::<$ty>::IMPLEMENTS_LISTEN;
            let impls_parse =
                $crate::internals::parse::wrappers::ParsePluginApi::<$ty>::IMPLEMENTS_PARSE;
            let impls_source =
                $crate::internals::source::wrappers::SourcePluginApi::<$ty>::IMPLEMENTS_SOURCE;

            assert!(
                impls_async || impls_extract || impls_listen || impls_parse || impls_source,
                "Plugin must implement at least one capability. If you really want a plugin without capabilities, use the #[no_capabilities] attribute"
            );
        };
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! base_plugin_ffi_wrappers {
    ($maj:expr; $min:expr; $patch:expr => #[$attr:meta] $ty:ty) => {
        #[$attr]
        pub extern "C-unwind" fn plugin_get_required_api_version() -> *const std::ffi::c_char {
            $crate::internals::base::wrappers::plugin_get_required_api_version::<
                { $maj },
                { $min },
                { $patch },
            >()
        }

        $crate::wrap_ffi! {
            #[$attr]
            use $crate::internals::base::wrappers: <$ty>;

            unsafe fn plugin_get_version() -> *const std::ffi::c_char;
            unsafe fn plugin_get_name() -> *const std::ffi::c_char;
            unsafe fn plugin_get_description() -> *const std::ffi::c_char;
            unsafe fn plugin_get_contact() -> *const std::ffi::c_char;
            unsafe fn plugin_get_init_schema(schema_type: *mut u32) -> *const std::ffi::c_char;
            unsafe fn plugin_init(
                args: *const falco_plugin::api::ss_plugin_init_input,
                rc: *mut i32,
            ) -> *mut falco_plugin::api::ss_plugin_t;
            unsafe fn plugin_destroy(plugin: *mut falco_plugin::api::ss_plugin_t) -> ();
            unsafe fn plugin_get_last_error(
                plugin: *mut falco_plugin::api::ss_plugin_t,
            ) -> *const std::ffi::c_char;
            unsafe fn plugin_set_config(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                config_input: *const falco_plugin::api::ss_plugin_set_config_input,
            ) -> falco_plugin::api::ss_plugin_rc;
            unsafe fn plugin_get_metrics(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                num_metrics: *mut u32,
            ) -> *mut falco_plugin::api::ss_plugin_metric;
        }

        #[allow(dead_code)]
        pub const fn __plugin_base_api() -> falco_plugin::api::plugin_api {
            use $crate::internals::async_event::wrappers::AsyncPluginFallbackApi;
            use $crate::internals::extract::wrappers::ExtractPluginFallbackApi;
            use $crate::internals::listen::wrappers::CaptureListenFallbackApi;
            use $crate::internals::parse::wrappers::ParsePluginFallbackApi;
            use $crate::internals::source::wrappers::SourcePluginFallbackApi;
            falco_plugin::api::plugin_api {
                get_required_api_version: Some(plugin_get_required_api_version),
                get_version: Some(plugin_get_version),
                get_name: Some(plugin_get_name),
                get_description: Some(plugin_get_description),
                get_contact: Some(plugin_get_contact),
                get_init_schema: Some(plugin_get_init_schema),
                init: Some(plugin_init),
                destroy: Some(plugin_destroy),
                get_last_error: Some(plugin_get_last_error),
                __bindgen_anon_1:
                    $crate::internals::source::wrappers::SourcePluginApi::<$ty>::SOURCE_API,
                __bindgen_anon_2:
                    $crate::internals::extract::wrappers::ExtractPluginApi::<$ty>::EXTRACT_API,
                __bindgen_anon_3:
                    $crate::internals::parse::wrappers::ParsePluginApi::<$ty>::PARSE_API,
                __bindgen_anon_4:
                    $crate::internals::async_event::wrappers::AsyncPluginApi::<$ty>::ASYNC_API,
                __bindgen_anon_5:
                    $crate::internals::listen::wrappers::CaptureListenApi::<$ty>::LISTEN_API,
                set_config: Some(plugin_set_config),
                get_metrics: Some(plugin_get_metrics),
            }
        }
    };
}
