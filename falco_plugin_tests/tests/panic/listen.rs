use falco_plugin::anyhow::{self, Error};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::RawEvent;
use falco_plugin::listen::{CaptureListenInput, CaptureListenPlugin};
use falco_plugin::source::{EventBatch, EventInput, SourcePlugin, SourcePluginInstance};
use falco_plugin::tables::TablesInput;
use falco_plugin::{static_plugin, FailureReason};
use falco_plugin_tests::{init_plugin, instantiate_tests, PlatformData, TestDriver};
use std::ffi::{CStr, CString};

struct ListenablePlugin;

impl Plugin for ListenablePlugin {
    const NAME: &'static CStr = c"listenable";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"panics in capture_open";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

struct ListenableInstance;

impl SourcePluginInstance for ListenableInstance {
    type Plugin = ListenablePlugin;

    fn next_batch(
        &mut self,
        _plugin: &mut Self::Plugin,
        _batch: &mut EventBatch,
    ) -> Result<(), Error> {
        Err(anyhow::anyhow!("done").context(FailureReason::Eof))
    }
}

impl SourcePlugin for ListenablePlugin {
    type Instance = ListenableInstance;
    const EVENT_SOURCE: &'static CStr = c"listenable";
    const PLUGIN_ID: u32 = 1112;
    type Event<'a> = RawEvent<'a>;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(ListenableInstance)
    }

    fn event_to_string(&mut self, _event: &EventInput<RawEvent>) -> Result<CString, Error> {
        Ok(CString::from(c"noop"))
    }
}

impl CaptureListenPlugin for ListenablePlugin {
    fn capture_open(&mut self, _listen_input: &CaptureListenInput) -> Result<(), Error> {
        panic!("listen panic")
    }

    fn capture_close(&mut self, _listen_input: &CaptureListenInput) -> Result<(), Error> {
        Ok(())
    }
}

static_plugin!(LISTENABLE_PLUGIN_API = ListenablePlugin);

fn test_listen_panic<D: TestDriver>() {
    let (driver, _plugin) = init_plugin::<D>(&LISTENABLE_PLUGIN_API, c"").unwrap();
    let res = driver.start_capture(ListenablePlugin::NAME, c"", PlatformData::Disabled);
    match res {
        Ok(_) => panic!("expected start_capture to fail"),
        Err(e) => {
            assert!(e.to_string().contains("listen panic"));
        }
    }
}

instantiate_tests!(test_listen_panic);
