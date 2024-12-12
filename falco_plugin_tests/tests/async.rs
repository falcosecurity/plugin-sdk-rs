use falco_plugin::anyhow::{self, Error};
use falco_plugin::async_event::{AsyncEvent, AsyncEventPlugin, AsyncHandler, BackgroundTask};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::{Event, EventMetadata};
use falco_plugin::extract::EventInput;
use falco_plugin::source::{EventBatch, SourcePlugin, SourcePluginInstance};
use falco_plugin::tables::TablesInput;
use falco_plugin::{static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::panic;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Default)]
struct DummyPlugin {
    task: Arc<BackgroundTask>,
    thread: Option<JoinHandle<Result<(), Error>>>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy async plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Default::default())
    }
}

struct DummyPluginInstance;

impl SourcePluginInstance for DummyPluginInstance {
    type Plugin = DummyPlugin;

    fn next_batch(
        &mut self,
        _plugin: &mut Self::Plugin,
        _batch: &mut EventBatch,
    ) -> Result<(), Error> {
        std::thread::sleep(Duration::from_millis(20));
        Err(anyhow::anyhow!("this plugin does nothing").context(FailureReason::Timeout))
    }
}

impl SourcePlugin for DummyPlugin {
    type Instance = DummyPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"dummy";
    const PLUGIN_ID: u32 = 1111;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(DummyPluginInstance)
    }

    fn event_to_string(&mut self, _event: &EventInput) -> Result<CString, Error> {
        Ok(CString::from(c"what event?"))
    }
}

impl AsyncEventPlugin for DummyPlugin {
    const ASYNC_EVENTS: &'static [&'static str] = &["dummy_async"];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];

    fn start_async(&mut self, handler: AsyncHandler) -> Result<(), Error> {
        if self.thread.is_some() {
            self.stop_async()?;
        }

        self.thread = Some(self.task.spawn(Duration::from_millis(100), move || {
            dbg!("emitting event");
            let event = AsyncEvent {
                plugin_id: Some(0),
                name: Some(c"dummy_async"),
                data: Some(b"hello"),
            };

            let metadata = EventMetadata::default();

            let event = Event {
                metadata,
                params: event,
            };
            handler.emit(event)?;

            let event = AsyncEvent {
                plugin_id: Some(0),
                name: Some(c"invalid_event_name"),
                data: Some(b"hello"),
            };

            let metadata = EventMetadata::default();

            let event = Event {
                metadata,
                params: event,
            };
            assert!(handler.emit(event).is_err());

            Ok(())
        })?);

        Ok(())
    }

    fn stop_async(&mut self) -> Result<(), Error> {
        dbg!("requesting shutdown");
        self.task.request_stop_and_notify()?;

        let Some(handle) = self.thread.take() else {
            return Ok(());
        };

        match handle.join() {
            Ok(res) => res,
            Err(e) => panic::resume_unwind(e),
        }
    }
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{init_plugin, instantiate_tests, CapturingTestDriver, TestDriver};

    fn test_async<D: TestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"").unwrap();
        let mut driver = driver.start_capture(super::DummyPlugin::NAME, c"").unwrap();

        let mut nevts = 0;

        while nevts < 10 {
            let event = driver.next_event();
            if event.is_ok() {
                nevts += 1;
            }
        }
    }

    instantiate_tests!(test_async);
}
