use falco_plugin_api::{
    plugin_api__bindgen_ty_4, ss_plugin_event, ss_plugin_owner_t, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED, ss_plugin_rc_SS_PLUGIN_SUCCESS,
    ss_plugin_rc_SS_PLUGIN_TIMEOUT, ss_plugin_t,
};
use std::collections::VecDeque;
use std::ffi::c_char;
use std::sync::{Arc, Mutex};

pub struct AsyncPlugin {
    plugin: *mut ss_plugin_t,
    api: *const plugin_api__bindgen_ty_4,

    last_event: Option<Vec<u8>>,
    event_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl AsyncPlugin {
    pub fn new(plugin: *mut ss_plugin_t, api: *const plugin_api__bindgen_ty_4) -> Self {
        Self {
            plugin,
            api,
            last_event: None,
            event_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn api(&self) -> &plugin_api__bindgen_ty_4 {
        unsafe { &*self.api }
    }

    fn owner(&mut self) -> *mut ss_plugin_owner_t {
        self as *mut _ as *mut _
    }

    pub fn on_capture_start(&mut self) -> Result<(), ss_plugin_rc> {
        let set_async_handler = self
            .api()
            .set_async_event_handler
            .ok_or(ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED)?;

        let rc = unsafe { set_async_handler(self.plugin, self.owner(), Some(async_handler)) };
        if rc == ss_plugin_rc_SS_PLUGIN_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }

    pub fn on_capture_stop(&mut self) -> Result<(), ss_plugin_rc> {
        let set_async_handler = self
            .api()
            .set_async_event_handler
            .ok_or(ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED)?;

        let rc = unsafe { set_async_handler(self.plugin, self.owner(), None) };
        if rc == ss_plugin_rc_SS_PLUGIN_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }

    pub fn next_event(&mut self) -> Result<*mut ss_plugin_event, ss_plugin_rc> {
        self.last_event = self.event_queue.lock().unwrap().pop_front();
        match &self.last_event {
            Some(evt) => Ok(evt.as_ptr().cast::<ss_plugin_event>().cast_mut()),
            None => Err(ss_plugin_rc_SS_PLUGIN_TIMEOUT),
        }
    }
}

unsafe extern "C-unwind" fn async_handler(
    owner: *mut ss_plugin_owner_t,
    event: *const ss_plugin_event,
    _err: *mut c_char,
) -> i32 {
    let owner = unsafe { &mut *(owner as *mut AsyncPlugin) };
    let evt_len = unsafe { (*event).len as usize };

    let event = event as *const u8;
    let event = unsafe { std::slice::from_raw_parts(event, evt_len) };

    owner.event_queue.lock().unwrap().push_back(event.to_vec());

    ss_plugin_rc_SS_PLUGIN_SUCCESS
}
