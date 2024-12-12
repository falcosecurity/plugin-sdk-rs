use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::{EventType, PPME_GENERIC_E};
use falco_plugin::event::events::{Event, EventMetadata};
use falco_plugin::event::fields::types::PT_SYSCALLID;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::source::{EventBatch, EventInput, SourcePlugin, SourcePluginInstance};
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin};
use std::ffi::{CStr, CString};

struct DummyPlugin;

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy no-op plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = String;

    fn new(_input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self, Error> {
        log::set_max_level(log::LevelFilter::Trace);
        if config != "testing" {
            anyhow::bail!("I only accept \"testing\" as the config string");
        }

        Ok(Self)
    }

    fn set_config(&mut self, config: Self::ConfigType) -> Result<(), Error> {
        if config != "testing" {
            anyhow::bail!("I only accept \"testing\" as the config string, even in an update");
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
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        batch.add(Event {
            metadata: EventMetadata { ts: 0, tid: 1 },
            params: PPME_GENERIC_E {
                id: Some(PT_SYSCALLID(1)),
                native_id: Some(1),
            },
        })?;

        Ok(())
    }
}

impl SourcePlugin for DummyPlugin {
    type Instance = DummyPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"";
    const PLUGIN_ID: u32 = 0;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(DummyPluginInstance)
    }

    fn event_to_string(&mut self, _event: &EventInput) -> Result<CString, Error> {
        Ok(CString::from(c"what event?"))
    }
}

struct DummyExtractPlugin;

impl Plugin for DummyExtractPlugin {
    const NAME: &'static CStr = c"dummy-extract";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy extract plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }

    fn set_config(&mut self, _config: Self::ConfigType) -> Result<(), Error> {
        Ok(())
    }
}
impl DummyExtractPlugin {
    fn extract_tid(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event = req.event.event()?;
        Ok(event.metadata.tid as u64)
    }
}

impl ExtractPlugin for DummyExtractPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("dummy.tid", &Self::extract_tid)];
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);
static_plugin!(EXTRACT_PLUGIN_API = DummyExtractPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{init_plugin, instantiate_tests, CapturingTestDriver, TestDriver};

    fn test_dummy_init<D: TestDriver>() {
        init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"testing").unwrap();
    }

    fn test_dummy_init_bad_config<D: TestDriver>() {
        let res = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"not testing");
        let res = res.unwrap_err().to_string();
        assert!(res.contains("I only accept \"testing\" as the config string"));
    }

    fn test_dummy_next<D: TestDriver>() {
        let (mut driver, _plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"testing").unwrap();
        let plugin = driver
            .register_plugin(&super::EXTRACT_PLUGIN_API, c"")
            .unwrap();
        driver.add_filterchecks(&plugin, c"syscall").unwrap();

        let mut driver = driver.start_capture(super::DummyPlugin::NAME, c"").unwrap();

        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.tid", &event)
                .unwrap()
                .unwrap(),
            "1"
        )
    }

    instantiate_tests!(
        test_dummy_init;
        test_dummy_init_bad_config;
        test_dummy_next);
}
