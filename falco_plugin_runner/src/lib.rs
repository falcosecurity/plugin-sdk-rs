mod event;
mod plugin;
mod tables;

pub use crate::plugin::ExtractedField;
pub use crate::plugin::Metric;
pub use crate::plugin::MetricType;
pub use crate::plugin::MetricValue;
pub use crate::plugin::ScapStatus;
pub use event::Event;

use crate::tables::Tables;
use plugin::Plugin;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::rc::Rc;

pub struct PluginRunner {
    plugins: Vec<Plugin>,
    tables: Rc<RefCell<Tables>>,
}

pub struct CapturingPluginRunner {
    plugins: Vec<Plugin>,
    tables: Rc<RefCell<Tables>>,
    evtnum: u64,
}

impl Default for PluginRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRunner {
    pub fn new() -> Self {
        Self {
            plugins: vec![],
            tables: Rc::new(RefCell::new(Tables::new())),
        }
    }

    pub fn register_plugin(
        &mut self,
        plugin: &'static falco_plugin_api::plugin_api,
        config: &CStr,
    ) -> anyhow::Result<()> {
        let plugin = Plugin::new(plugin, Rc::clone(&self.tables), config)?;
        self.plugins.push(plugin);

        Ok(())
    }

    pub fn start_capture(mut self) -> anyhow::Result<CapturingPluginRunner> {
        for plugin in &mut self.plugins {
            plugin
                .on_capture_start()
                .map_err(|e| anyhow::anyhow!("Got API error {e}"))?;
        }

        Ok(CapturingPluginRunner {
            plugins: self.plugins,
            tables: self.tables,
            evtnum: 0,
        })
    }
}

impl CapturingPluginRunner {
    pub fn stop_capture(mut self) -> anyhow::Result<PluginRunner> {
        for plugin in &mut self.plugins {
            plugin
                .on_capture_stop()
                .map_err(|e| anyhow::anyhow!("Got API error {e}"))?;
        }

        Ok(PluginRunner {
            plugins: std::mem::take(&mut self.plugins),
            tables: std::mem::take(&mut self.tables),
        })
    }

    fn get_next_event(&mut self) -> anyhow::Result<Event> {
        self.evtnum += 1;
        for plugin in &mut self.plugins {
            match plugin.next_event() {
                Ok(mut event) => {
                    event.evt_num = Some(self.evtnum);
                    return Ok(event);
                }
                Err(e) => match e.downcast_ref::<ScapStatus>() {
                    Some(ScapStatus::Timeout) => continue,
                    _ => return Err(e),
                },
            }
        }

        Err(anyhow::anyhow!("Timeout").context(ScapStatus::Timeout))
    }

    pub fn next_event(&mut self) -> anyhow::Result<Event> {
        let event = self.get_next_event()?;

        for plugin in &mut self.plugins {
            plugin.on_event(&event)?;
        }

        Ok(event)
    }

    pub fn extract_field(
        &mut self,
        event: &Event,
        field: &str,
    ) -> Option<Result<ExtractedField, falco_plugin_api::ss_plugin_rc>> {
        if field == "evt.plugininfo" {
            return if let Some(func) = event.to_string {
                let event_input = event.to_event_input();
                let cs = unsafe { func(event.source_plugin, &event_input) };
                if cs.is_null() {
                    Some(Ok(ExtractedField::None))
                } else {
                    let cs = CString::from(unsafe { CStr::from_ptr(cs) });
                    Some(Ok(ExtractedField::String(cs)))
                }
            } else {
                Some(Ok(ExtractedField::None))
            };
        }

        for plugin in &mut self.plugins {
            if let Some(res) = plugin.extract_field(event, field) {
                return Some(res);
            }
        }

        None
    }

    pub fn get_metrics(&mut self) -> Vec<Metric> {
        self.plugins
            .iter_mut()
            .flat_map(|p| p.get_metrics())
            .collect()
    }
}

impl Drop for CapturingPluginRunner {
    fn drop(&mut self) {
        for plugin in &mut self.plugins {
            plugin.on_capture_stop().ok();
        }
    }
}
