use crate::event::Event;
use falco_plugin_api::{plugin_api, ss_plugin_t};
use std::ffi::{c_char, CStr};

pub struct EventSourceFilter {
    event_types: Vec<u16>,
    event_sources: Vec<String>,
}

impl EventSourceFilter {
    pub fn new(
        plugin: *mut ss_plugin_t,
        api: &plugin_api,
        event_types_fn: Option<unsafe extern "C-unwind" fn(*mut u32, *mut ss_plugin_t) -> *mut u16>,
        event_sources_fn: Option<unsafe extern "C-unwind" fn() -> *const c_char>,
    ) -> Result<Self, anyhow::Error> {
        let mut event_sources = match event_sources_fn {
            Some(event_sources_fn) => {
                let sources = unsafe { event_sources_fn() };
                if sources.is_null() {
                    Vec::new()
                } else {
                    let sources = unsafe { CStr::from_ptr(sources) };
                    serde_json::from_slice(sources.to_bytes())?
                }
            }
            None => Vec::new(),
        };

        if event_sources.is_empty() {
            if let Some(source) = api.__bindgen_anon_1.get_event_source {
                let source = unsafe { source() };
                if !source.is_null() {
                    let source = unsafe { CStr::from_ptr(source) };
                    let source = source.to_string_lossy().into_owned();
                    event_sources.push(source);
                }
            }
        }

        let mut event_types = match event_types_fn {
            Some(event_types_fn) => {
                let mut numtypes = 0u32;
                let types = unsafe { event_types_fn(&mut numtypes, plugin) };
                if types.is_null() {
                    Vec::new()
                } else {
                    let types = unsafe { std::slice::from_raw_parts(types, numtypes as usize) };
                    types.to_vec()
                }
            }
            None => Vec::new(),
        };

        if event_types.is_empty() && event_sources.iter().all(|v| v.as_str() != "syscall") {
            event_types.push(322); // PLUGINEVENT_E
        }

        Ok(Self {
            event_types,
            event_sources,
        })
    }

    pub fn matches(&self, event: &Event) -> bool {
        if !self.event_sources.is_empty() {
            let event_source = unsafe { CStr::from_ptr(event.source).to_bytes() };
            if self
                .event_sources
                .iter()
                .all(|v| v.as_bytes() != event_source)
            {
                return false;
            }
        }

        if !self.event_types.is_empty() {
            let event_type = unsafe { (*event.buf).type_ };
            if !self.event_types.contains(&event_type) {
                return false;
            }
        }

        true
    }
}
