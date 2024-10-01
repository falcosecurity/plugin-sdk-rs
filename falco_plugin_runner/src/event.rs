use falco_plugin_api::ss_plugin_t;
use std::ffi::c_char;

#[derive(Debug)]
pub struct Event {
    pub source: *const c_char,
    pub source_plugin: *mut ss_plugin_t,
    pub to_string: Option<
        unsafe extern "C-unwind" fn(
            *mut falco_plugin_api::ss_plugin_t,
            *const falco_plugin_api::ss_plugin_event_input,
        ) -> *const c_char,
    >,
    pub buf: *mut falco_plugin_api::ss_plugin_event,
    pub evt_num: Option<u64>,
}

impl Event {
    pub fn to_event_input(&self) -> falco_plugin_api::ss_plugin_event_input {
        falco_plugin_api::ss_plugin_event_input {
            evt: self.buf,
            evtnum: self.evt_num.unwrap_or_default(),
            evtsrc: self.source,
        }
    }
}
