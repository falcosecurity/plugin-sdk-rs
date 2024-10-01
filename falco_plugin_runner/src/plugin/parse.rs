use crate::event::Event;
use crate::plugin::event_source_filter::EventSourceFilter;
use crate::plugin::get_last_owner_error;
use crate::tables::{TABLE_READER, TABLE_READER_EXT, TABLE_WRITER, TABLE_WRITER_EXT};
use falco_plugin_api::{plugin_api__bindgen_ty_3, ss_plugin_owner_t, ss_plugin_t};

pub struct ParsePlugin {
    owner: *mut ss_plugin_owner_t,
    plugin: *mut ss_plugin_t,
    api: *const plugin_api__bindgen_ty_3,
    filter: EventSourceFilter,
}

impl ParsePlugin {
    pub fn new(
        owner: *mut ss_plugin_owner_t,
        plugin: *mut ss_plugin_t,
        api: *const plugin_api__bindgen_ty_3,
        filter: EventSourceFilter,
    ) -> Self {
        Self {
            owner,
            plugin,
            api,
            filter,
        }
    }

    fn api(&self) -> &plugin_api__bindgen_ty_3 {
        unsafe { &*self.api }
    }

    pub fn on_event(&mut self, event: &Event) -> Result<(), falco_plugin_api::ss_plugin_rc> {
        if !self.filter.matches(event) {
            return Ok(());
        }

        let event_input = event.to_event_input();
        let parse_input = falco_plugin_api::ss_plugin_event_parse_input {
            owner: self.owner,
            get_owner_last_error: Some(get_last_owner_error),
            table_reader: TABLE_READER,
            table_writer: TABLE_WRITER,
            table_reader_ext: &TABLE_READER_EXT as *const _ as *mut _,
            table_writer_ext: &TABLE_WRITER_EXT as *const _ as *mut _,
        };

        let parse = self
            .api()
            .parse_event
            .ok_or(falco_plugin_api::ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED)?;

        let rc = unsafe { parse(self.plugin, &event_input, &parse_input) };
        if rc == falco_plugin_api::ss_plugin_rc_SS_PLUGIN_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }
}
