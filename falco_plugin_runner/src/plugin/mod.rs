mod async_event;
mod event_source_filter;
mod extract;
mod listen;
mod parse;
mod source;

pub use extract::ExtractedField;
use std::cell::RefCell;

use crate::event::Event;
use crate::plugin::async_event::AsyncPlugin;
use crate::plugin::event_source_filter::EventSourceFilter;
use crate::plugin::extract::ExtractPlugin;
use crate::plugin::listen::CaptureListenPlugin;
use crate::plugin::parse::ParsePlugin;
use crate::plugin::source::SourcePlugin;
use crate::tables::{Tables, TABLE_FIELDS, TABLE_FIELDS_EXT, TABLE_READER_EXT, TABLE_WRITER_EXT};
use anyhow::{anyhow, Context};
use falco_plugin_api::{
    ss_plugin_event, ss_plugin_log_severity, ss_plugin_owner_t, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_EOF, ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_TIMEOUT,
    ss_plugin_state_type, ss_plugin_table_info, ss_plugin_table_input, ss_plugin_table_t,
};
use std::ffi::{c_char, CStr, CString};
use std::fmt::{Display, Formatter};
use std::rc::Rc;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ScapStatus {
    Ok,
    Failure,
    Timeout,
    Eof,
    NotSupported,
    Other(i32),
}

impl Display for ScapStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScapStatus::Ok => f.write_str("OK"),
            ScapStatus::Failure => f.write_str("Failure"),
            ScapStatus::Timeout => f.write_str("Timeout"),
            ScapStatus::Eof => f.write_str("Eof"),
            ScapStatus::NotSupported => f.write_str("NotSupported"),
            ScapStatus::Other(rc) => write!(f, "Other({})", rc),
        }
    }
}

impl From<i32> for ScapStatus {
    fn from(value: i32) -> Self {
        match value {
            0 => ScapStatus::Ok,
            1 => ScapStatus::Failure,
            -1 => ScapStatus::Timeout,
            6 => ScapStatus::Eof,
            9 => ScapStatus::NotSupported,
            e => ScapStatus::Other(e),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MetricType {
    Monotonic,
    NonMonotonic,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MetricValue {
    U32(u32),
    S32(i32),
    U64(u64),
    I64(i64),
    Double(f64),
    Float(f32),
    Int(i32),
}

pub struct Metric {
    pub name: String,
    pub metric_type: MetricType,
    pub value: MetricValue,
}

pub struct Plugin {
    api: &'static falco_plugin_api::plugin_api,
    plugin: *mut falco_plugin_api::ss_plugin_t,
    tables: Rc<RefCell<Tables>>,
    capturing: bool,

    source: Option<SourcePlugin>,
    parse: Option<ParsePlugin>,
    extract: Option<ExtractPlugin>,
    async_event: Option<AsyncPlugin>,
    capture_listen: Option<CaptureListenPlugin>,
}

impl Plugin {
    fn api(&self) -> &falco_plugin_api::plugin_api {
        self.api
    }

    pub fn new(
        api: &'static falco_plugin_api::plugin_api,
        tables: Rc<RefCell<Tables>>,
        config: &CStr,
    ) -> anyhow::Result<Self> {
        let mut this = Self {
            api,
            plugin: std::ptr::null_mut(),
            tables: Rc::clone(&tables),
            capturing: false,

            source: None,
            parse: None,
            extract: None,
            async_event: None,
            capture_listen: None,
        };
        this.init(config)?;
        Ok(this)
    }

    pub fn name(&self) -> *const c_char {
        if let Some(get_name) = self.api().get_name {
            unsafe { get_name() }
        } else {
            std::ptr::null()
        }
    }

    pub fn last_error(&self) -> Option<CString> {
        let get_last_error = self.api().get_last_error?;
        let last_error = unsafe { get_last_error(self.plugin) };
        if last_error.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(last_error) }.to_owned())
        }
    }

    pub fn supports_source(&self) -> bool {
        self.api().__bindgen_anon_1.open.is_some() // ... and all the other methods
    }

    pub fn supports_extract(&self) -> bool {
        self.api().__bindgen_anon_2.extract_fields.is_some() // ... etc.
    }

    pub fn supports_parse(&self) -> bool {
        self.api().__bindgen_anon_3.parse_event.is_some() // ... etc.
    }

    pub fn supports_async(&self) -> bool {
        self.api()
            .__bindgen_anon_4
            .set_async_event_handler
            .is_some() // ... etc.
    }

    pub fn supports_capture_listen(&self) -> bool {
        self.api().__bindgen_anon_5.capture_open.is_some() // ... etc.
    }

    fn owner(&self) -> *mut ss_plugin_owner_t {
        self as *const _ as *mut ss_plugin_owner_t
    }

    fn init(&mut self, config: &CStr) -> anyhow::Result<()> {
        let tables = self.tables.borrow();
        let tables_input = falco_plugin_api::ss_plugin_init_tables_input {
            list_tables: Some(list_tables),
            get_table: Some(get_table),
            add_table: Some(add_table),
            fields: TABLE_FIELDS,
            fields_ext: &TABLE_FIELDS_EXT as *const _ as *mut _,
            reader_ext: &TABLE_READER_EXT as *const _ as *mut _,
            writer_ext: &TABLE_WRITER_EXT as *const _ as *mut _,
        };

        let input = falco_plugin_api::ss_plugin_init_input {
            config: config.as_ptr(),
            owner: self.owner(),
            get_owner_last_error: Some(get_last_owner_error),
            tables: &tables_input,
            log_fn: Some(log),
        };
        drop(tables);

        let mut rc = 0i32;
        let init = self
            .api()
            .init
            .ok_or_else(|| anyhow::anyhow!("Plugin does not have an init method"))?;

        let plugin = unsafe { init(&input, &mut rc) };
        self.plugin = plugin;
        if rc != falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS {
            return Err(anyhow::anyhow!(
                "Plugin initialization failed, rc {rc}, err {}",
                self.last_error().unwrap_or_default().to_string_lossy()
            ));
        }

        let mut has_any_capabilities = false;

        if self.supports_source() {
            has_any_capabilities = true;
            self.source = Some(SourcePlugin::new(self.plugin, &self.api.__bindgen_anon_1))
        }

        if self.supports_extract() {
            has_any_capabilities = true;

            let filter = EventSourceFilter::new(
                self.plugin,
                self.api,
                self.api.__bindgen_anon_2.get_extract_event_types,
                self.api.__bindgen_anon_2.get_extract_event_sources,
            )?;

            self.extract = Some(ExtractPlugin::new(
                self.owner(),
                self.plugin,
                &self.api.__bindgen_anon_2,
                filter,
            )?);
        }

        if self.supports_parse() {
            has_any_capabilities = true;

            let filter = EventSourceFilter::new(
                self.plugin,
                self.api,
                self.api.__bindgen_anon_3.get_parse_event_types,
                self.api.__bindgen_anon_3.get_parse_event_sources,
            )?;

            self.parse = Some(ParsePlugin::new(
                self.owner(),
                self.plugin,
                &self.api.__bindgen_anon_3,
                filter,
            ));
        }

        if self.supports_async() {
            has_any_capabilities = true;
            self.async_event = Some(AsyncPlugin::new(self.plugin, &self.api.__bindgen_anon_4))
        }

        if self.supports_capture_listen() {
            has_any_capabilities = true;
            self.capture_listen = Some(CaptureListenPlugin::new(
                self.plugin,
                &self.api.__bindgen_anon_5,
            ))
        }

        if !has_any_capabilities {
            anyhow::bail!("Plugin does not have any capabilities");
        }

        Ok(())
    }

    pub fn on_capture_start(&mut self) -> anyhow::Result<()> {
        if let Some(ref mut source) = self.source {
            source.on_capture_start().map_err(|e| {
                anyhow!(
                    "failed to start capture, rc {e}, err {:?}",
                    self.last_error()
                )
            })?;
        }

        if let Some(ref mut async_event) = self.async_event {
            async_event.on_capture_start().map_err(|e| {
                anyhow!(
                    "failed to notify async capture start, rc {e}, err {:?}",
                    self.last_error()
                )
            })?;
        }

        if let Some(ref mut capture_listen) = self.capture_listen {
            capture_listen.on_capture_start().map_err(|e| {
                anyhow!(
                    "failed to notify capture_listen plugin, rc {e}, err {:?}",
                    self.last_error()
                )
            })?;
        }

        self.capturing = true;
        Ok(())
    }

    pub fn on_capture_stop(&mut self) -> anyhow::Result<()> {
        // if we fail, we at least tried, so don't assert in the Drop impl
        self.capturing = false;

        if let Some(ref mut source) = self.source {
            source.on_capture_stop().map_err(|e| {
                anyhow!(
                    "failed to stop capture, rc {e}, err {:?}",
                    self.last_error()
                )
            })?;
        }

        if let Some(ref mut async_event) = self.async_event {
            async_event.on_capture_stop().map_err(|e| {
                anyhow!(
                    "failed to notify async plugin, rc {e}, err {:?}",
                    self.last_error()
                )
            })?;
        }

        if let Some(ref mut capture_listen) = self.capture_listen {
            capture_listen.on_capture_stop().map_err(|e| {
                anyhow!(
                    "failed to notify capture listen plugin, rc {e}, err {:?}",
                    self.last_error()
                )
            })?;
        }

        Ok(())
    }

    pub fn get_metrics(&mut self) -> Vec<Metric> {
        let Some(get_metrics) = self.api().get_metrics else {
            return Vec::new();
        };

        let mut nmetrics = 0u32;
        let metrics = unsafe { get_metrics(self.plugin, &mut nmetrics) };
        let metrics = unsafe { std::slice::from_raw_parts(metrics, nmetrics as usize) };

        metrics.iter().filter_map(|m| {
            if m.name.is_null() {
                return None;
            }
            let name = unsafe { CStr::from_ptr(m.name) };
            let name = std::str::from_utf8(name.to_bytes()).ok()?;

            let plugin_name = self.name();
            if plugin_name.is_null() {
                return None;
            }
            let plugin_name = unsafe { CStr::from_ptr(plugin_name) };
            let plugin_name = std::str::from_utf8(plugin_name.to_bytes()).ok()?;

            let name = format!("{plugin_name}.{name}");

            let metric_type = match m.type_ {
                falco_plugin_api::ss_plugin_metric_type_SS_PLUGIN_METRIC_TYPE_MONOTONIC => MetricType::Monotonic,
                falco_plugin_api::ss_plugin_metric_type_SS_PLUGIN_METRIC_TYPE_NON_MONOTONIC => MetricType::NonMonotonic,
                _ => return None,
            };

            let value = unsafe { match m.value_type {
                falco_plugin_api::ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_U32 => MetricValue::U32(m.value.u32_),
                falco_plugin_api::ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_U64 => MetricValue::U64(m.value.u64_),
                falco_plugin_api::ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_S64 => MetricValue::I64(m.value.s64),
                falco_plugin_api::ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_D => MetricValue::Double(m.value.d),
                falco_plugin_api::ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_F => MetricValue::Float(m.value.f),
                falco_plugin_api::ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_I => MetricValue::Int(m.value.i),
                _ => return None,
            }};

            Some(Metric {
                name,
                metric_type,
                value,
            })
        }).collect()
    }

    fn decorate_event(&mut self, buf: *mut ss_plugin_event) -> Event {
        Event {
            source: self.name(),
            source_plugin: self.plugin,
            to_string: self.api.__bindgen_anon_1.event_to_string,
            buf,
            evt_num: None,
        }
    }

    #[allow(non_upper_case_globals)]
    pub fn next_event(&mut self) -> anyhow::Result<Event> {
        if let Some(ref mut async_event) = self.async_event {
            let event = async_event.next_event();
            match event {
                Ok(event) => return Ok(self.decorate_event(event)),
                Err(ss_plugin_rc_SS_PLUGIN_TIMEOUT) => {}
                Err(e) => {
                    return Err(anyhow!(
                        "failed to get next async event, rc {e}, err {:?}",
                        self.last_error()
                    ))
                    .context(ScapStatus::from(e))?;
                }
            }
        }

        if let Some(ref mut source) = self.source {
            let event = source.next_event();
            return match event {
                Ok(event) => Ok(self.decorate_event(event)),
                Err(ss_plugin_rc_SS_PLUGIN_TIMEOUT) => {
                    Err(anyhow::anyhow!("timeout")).context(ScapStatus::Timeout)
                }
                Err(ss_plugin_rc_SS_PLUGIN_EOF) => {
                    Err(anyhow::anyhow!("timeout")).context(ScapStatus::Eof)
                }
                Err(e) => Err(anyhow!(
                    "failed to get next event, rc {e}, err {:?}",
                    self.last_error()
                ))
                .context(ScapStatus::from(e))?,
            };
        }

        Err(anyhow::anyhow!("no source/async plugin here")).context(ScapStatus::NotSupported)
    }

    pub fn on_event(&mut self, event: &Event) -> anyhow::Result<()> {
        if let Some(ref mut parse) = self.parse {
            parse.on_event(event).map_err(|e| {
                anyhow::anyhow!(
                    "failed to parse event, rc: {e}, err: {:?}",
                    self.last_error()
                )
            })?;
        }

        Ok(())
    }

    pub fn extract_field(
        &mut self,
        event: &Event,
        field: &str,
    ) -> Option<Result<ExtractedField, ss_plugin_rc>> {
        if let Some(ref mut extract) = self.extract {
            extract.extract(event, field)
        } else {
            None
        }
    }
}

extern "C-unwind" fn get_last_owner_error(_owner: *mut ss_plugin_owner_t) -> *const c_char {
    std::ptr::null()
}

unsafe extern "C-unwind" fn log(
    _owner: *mut ss_plugin_owner_t,
    component: *const c_char,
    msg: *const c_char,
    severity: ss_plugin_log_severity,
) {
    eprint!("<{severity}>");
    if !component.is_null() {
        eprint!(" {:?}:", CStr::from_ptr(component));
    }
    if !msg.is_null() {
        eprint!(" {:?}", CStr::from_ptr(msg));
    }
    eprintln!();
}

unsafe extern "C-unwind" fn list_tables(
    owner: *mut ss_plugin_owner_t,
    ntables: *mut u32,
) -> *mut ss_plugin_table_info {
    let Some(owner) = (unsafe { (owner as *mut Plugin).as_mut() }) else {
        return std::ptr::null_mut();
    };

    let mut tables = owner.tables.borrow_mut();
    let tables = tables.list_tables();
    unsafe { *ntables = tables.len() as u32 };
    tables.as_mut_ptr()
}

pub unsafe extern "C-unwind" fn get_table(
    owner: *mut ss_plugin_owner_t,
    name: *const ::std::os::raw::c_char,
    key_type: ss_plugin_state_type,
) -> *mut ss_plugin_table_t {
    let Some(owner) = (unsafe { (owner as *mut Plugin).as_mut() }) else {
        return std::ptr::null_mut();
    };

    if name.is_null() {
        return std::ptr::null_mut();
    }
    let name = CStr::from_ptr(name);

    let tables = owner.tables.borrow();
    match tables.get_table(name, key_type) {
        Some(table) => table as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

pub unsafe extern "C-unwind" fn add_table(
    owner: *mut ss_plugin_owner_t,
    table_input: *const ss_plugin_table_input,
) -> ss_plugin_rc {
    let Some(owner) = (unsafe { (owner as *mut Plugin).as_mut() }) else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    let Some(table_input) = (unsafe { table_input.as_ref() }) else {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    };

    if table_input.name.is_null() {
        return ss_plugin_rc_SS_PLUGIN_FAILURE;
    }
    let name = CStr::from_ptr(table_input.name);

    let mut tables = owner.tables.borrow_mut();
    tables.add_table(name, table_input)
}

impl Drop for Plugin {
    fn drop(&mut self) {
        if self.plugin.is_null() {
            return;
        }

        assert!(!self.capturing);

        let Some(destroy) = self.api().destroy else {
            return;
        };
        unsafe { destroy(self.plugin) }
    }
}
