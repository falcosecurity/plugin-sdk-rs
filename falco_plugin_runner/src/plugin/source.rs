use falco_plugin_api::{plugin_api__bindgen_ty_1, ss_plugin_event, ss_plugin_rc, ss_plugin_t};

pub struct SourcePlugin {
    plugin: *mut ss_plugin_t,
    api: *const plugin_api__bindgen_ty_1,
    instance: *mut falco_plugin_api::ss_instance_t,
    event_batch: *mut *mut ss_plugin_event,
    batch_size: usize,
    current_event: usize,
}

impl SourcePlugin {
    pub fn new(plugin: *mut ss_plugin_t, api: *const plugin_api__bindgen_ty_1) -> Self {
        Self {
            plugin,
            api,
            instance: std::ptr::null_mut(),
            event_batch: std::ptr::null_mut(),
            batch_size: 0,
            current_event: 0,
        }
    }

    fn api(&self) -> &plugin_api__bindgen_ty_1 {
        unsafe { &*self.api }
    }

    pub fn on_capture_start(&mut self) -> Result<(), ss_plugin_rc> {
        let open = self
            .api()
            .open
            .ok_or(falco_plugin_api::ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED)?;

        let config = std::ptr::null(); // TODO
        let mut rc = 0i32;
        let instance = unsafe { open(self.plugin, config, &mut rc) };
        if rc == falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS {
            self.instance = instance;
            Ok(())
        } else {
            Err(rc)
        }
    }

    pub fn on_capture_stop(&mut self) -> Result<(), ss_plugin_rc> {
        let close = self
            .api()
            .close
            .ok_or(falco_plugin_api::ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED)?;
        unsafe { close(self.plugin, self.instance) };
        Ok(())
    }

    pub fn next_event(&mut self) -> Result<*mut ss_plugin_event, ss_plugin_rc> {
        if self.current_event >= self.batch_size {
            let next = self
                .api()
                .next_batch
                .ok_or(falco_plugin_api::ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED)?;
            let mut nevts = 0u32;
            let rc = unsafe {
                next(
                    self.plugin,
                    self.instance,
                    &mut nevts,
                    &mut self.event_batch,
                )
            };
            self.batch_size = nevts as usize;
            self.current_event = 0;
            if rc != falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS {
                self.batch_size = 0;
                return Err(rc);
            }
        }

        if self.current_event < self.batch_size {
            let evt = unsafe { self.event_batch.add(self.current_event) };
            self.current_event += 1;
            unsafe { Ok(*evt) }
        } else {
            Err(falco_plugin_api::ss_plugin_rc_SS_PLUGIN_TIMEOUT)
        }
    }
}
