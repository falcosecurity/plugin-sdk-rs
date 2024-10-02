use falco_plugin::anyhow::Error;
use falco_plugin::base::{Json, Plugin};
use falco_plugin::schemars::JsonSchema;
use falco_plugin::serde::Deserialize;
use falco_plugin::source::{EventBatch, EventInput, SourcePlugin, SourcePluginInstance};
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin, FailureReason};
use std::ffi::{CStr, CString};

struct DummyPlugin;

#[derive(JsonSchema, Deserialize)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
struct DummyConfig {
    five: u64,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy no-op plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = Json<DummyConfig>;

    fn new(_input: Option<&TablesInput>, Json(config): Self::ConfigType) -> Result<Self, Error> {
        if config.five != 5 {
            anyhow::bail!("I wanted five");
        }

        Ok(Self)
    }

    fn set_config(&mut self, Json(config): Self::ConfigType) -> Result<(), Error> {
        if config.five != 5 {
            anyhow::bail!("I wanted five");
        }

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
        Ok(DummyPluginInstance)
    }

    fn event_to_string(&mut self, _event: &EventInput) -> Result<CString, Error> {
        Ok(CString::from(c"what event?"))
    }
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{
        init_plugin, instantiate_tests, CapturingTestDriver, ScapStatus, TestDriver,
    };

    fn test_dummy_init<D: TestDriver>() {
        init_plugin::<D>(super::DUMMY_PLUGIN_API, c"{\"five\": 5}").unwrap();
    }

    fn test_dummy_init_bad_config_schema<D: TestDriver>() {
        let res = init_plugin::<D>(super::DUMMY_PLUGIN_API, c"{\"six\": 6}");

        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Missing required property 'five'"));
    }

    fn test_dummy_init_bad_config_value<D: TestDriver>() {
        let res = init_plugin::<D>(super::DUMMY_PLUGIN_API, c"{\"five\": 6}");

        assert!(res.unwrap_err().to_string().contains("I wanted five"));
    }

    fn test_dummy_next<D: TestDriver>() {
        let (driver, _plugin) =
            init_plugin::<D>(super::DUMMY_PLUGIN_API, c"{\"five\": 5}").unwrap();
        let mut driver = driver.start_capture(super::DummyPlugin::NAME, c"").unwrap();

        let event = driver.next_event();
        assert!(matches!(event, Err(ScapStatus::Eof)))
    }

    instantiate_tests!(
        test_dummy_init;
        test_dummy_init_bad_config_schema;
        test_dummy_init_bad_config_value;
        test_dummy_next
    );
}
