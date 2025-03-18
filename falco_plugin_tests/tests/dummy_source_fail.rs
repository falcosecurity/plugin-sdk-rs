use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::source::{EventBatch, EventInput, SourcePlugin, SourcePluginInstance};
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin, FailureReason};
use std::ffi::{CStr, CString};

struct DummyPlugin;

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy no-op plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        log::set_max_level(log::LevelFilter::Trace);
        Ok(Self)
    }

    fn set_config(&mut self, _config: Self::ConfigType) -> Result<(), Error> {
        Ok(())
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
        Err(anyhow::anyhow!("this plugin does nothing").context(FailureReason::Eof))
    }
}

impl SourcePlugin for DummyPlugin {
    type Instance = DummyPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"dummy";
    const PLUGIN_ID: u32 = 1111;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        anyhow::bail!("failed!")
    }

    fn event_to_string(&mut self, _event: &EventInput) -> Result<CString, Error> {
        Ok(CString::from(c"what event?"))
    }
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{init_plugin, instantiate_tests, TestDriver};

    fn test_dummy_next<D: TestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"").unwrap();
        assert!(driver.start_capture(super::DummyPlugin::NAME, c"").is_err());
    }

    instantiate_tests!(test_dummy_next);
}
