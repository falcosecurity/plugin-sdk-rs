use crate::plugin::base::PluginWrapper;
use crate::plugin::error::ffi_result::FfiResult;
use crate::plugin::event::EventInput;
use crate::plugin::extract::ExtractPlugin;
use crate::tables::LazyTableReader;
use falco_plugin_api::plugin_api__bindgen_ty_2 as extract_plugin_api;
use falco_plugin_api::ss_plugin_rc;
use falco_plugin_api::{ss_plugin_event_input, ss_plugin_rc_SS_PLUGIN_FAILURE};
use falco_plugin_api::{ss_plugin_field_extract_input, ss_plugin_t};
use std::any::TypeId;
use std::collections::BTreeMap;
use std::ffi::{c_char, CString};
use std::sync::Mutex;

pub trait ExtractPluginFallbackApi {
    const EXTRACT_API: extract_plugin_api = extract_plugin_api {
        get_extract_event_types: None,
        get_extract_event_sources: None,
        get_fields: None,
        extract_fields: None,
    };
}
impl<T> ExtractPluginFallbackApi for T {}

#[allow(missing_debug_implementations)]
pub struct ExtractPluginApi<T>(std::marker::PhantomData<T>);

impl<T: ExtractPlugin> ExtractPluginApi<T> {
    pub const EXTRACT_API: extract_plugin_api = extract_plugin_api {
        get_extract_event_types: Some(plugin_get_extract_event_types::<T>),
        get_extract_event_sources: Some(plugin_get_extract_event_sources::<T>),
        get_fields: Some(plugin_get_fields::<T>),
        extract_fields: Some(plugin_extract_fields::<T>),
    };
}

pub extern "C-unwind" fn plugin_get_fields<T: ExtractPlugin>() -> *const c_char {
    T::get_fields().as_ptr()
}

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_get_extract_event_types<T: ExtractPlugin>(
    numtypes: *mut u32,
    _plugin: *mut ss_plugin_t,
) -> *mut u16 {
    let types = T::EVENT_TYPES;
    unsafe { *numtypes = types.len() as u32 };
    types.as_ptr() as *const u16 as *mut u16 // TODO(spec): this should ****really**** be const
}

//noinspection DuplicatedCode
pub extern "C-unwind" fn plugin_get_extract_event_sources<T: ExtractPlugin>() -> *const c_char {
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

/// # Safety
///
/// All pointers must be valid
pub unsafe extern "C-unwind" fn plugin_extract_fields<T: ExtractPlugin>(
    plugin: *mut ss_plugin_t,
    event_input: *const ss_plugin_event_input,
    extract_input: *const ss_plugin_field_extract_input,
) -> ss_plugin_rc {
    let plugin = plugin as *mut PluginWrapper<T>;
    unsafe {
        let Some(plugin) = plugin.as_mut() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let Some(ref mut actual_plugin) = &mut plugin.plugin else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let Some(event_input) = event_input.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let event_input = EventInput(*event_input);

        let Some(extract_input) = extract_input.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let fields =
            std::slice::from_raw_parts_mut(extract_input.fields, extract_input.num_fields as usize);

        let Some(reader_ext) = extract_input.table_reader_ext.as_ref() else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };

        let table_reader = LazyTableReader::new(reader_ext, actual_plugin.last_error.clone());

        plugin.field_storage.reset();
        actual_plugin
            .plugin
            .extract_fields(
                &event_input,
                &table_reader,
                fields,
                &mut plugin.field_storage,
            )
            .rc(&mut plugin.error_buf)
    }
}

/// # Register an extract plugin
///
/// This macro must be called at most once in a crate (it generates public functions with fixed
/// `#[no_mangle`] names) with a type implementing [`ExtractPlugin`] as the sole parameter.
#[macro_export]
macro_rules! extract_plugin {
    ($ty:ty) => {
        $crate::wrap_ffi! {
            #[no_mangle]
            use $crate::internals::extract::wrappers: <$ty>;

            unsafe fn plugin_get_extract_event_sources() -> *const ::std::ffi::c_char;
            unsafe fn plugin_get_extract_event_types(
                numtypes: *mut u32,
                plugin: *mut falco_plugin::api::ss_plugin_t,
            ) -> *mut u16;
            unsafe fn plugin_get_fields() -> *const ::std::ffi::c_char;
            unsafe fn plugin_extract_fields(
                plugin: *mut falco_plugin::api::ss_plugin_t,
                event_input: *const falco_plugin::api::ss_plugin_event_input,
                extract_input: *const falco_plugin::api::ss_plugin_field_extract_input,
            ) -> i32;
        }

        #[allow(dead_code)]
        fn __typecheck_plugin_extract_api() -> falco_plugin::api::plugin_api__bindgen_ty_2 {
            falco_plugin::api::plugin_api__bindgen_ty_2 {
                get_extract_event_sources: Some(plugin_get_extract_event_sources),
                get_extract_event_types: Some(plugin_get_extract_event_types),
                get_fields: Some(plugin_get_fields),
                extract_fields: Some(plugin_extract_fields),
            }
        }
    };
}
