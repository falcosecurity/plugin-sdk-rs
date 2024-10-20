use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::source::{EventBatch, EventInput, SourcePlugin, SourcePluginInstance};
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, FailureReason};
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

// static linking
#[cfg(linkage = "static")]
use falco_plugin::static_plugin;

#[cfg(linkage = "static")]
static_plugin!(MY_PLUGIN = DummyPlugin);

// dynamic linking
#[cfg(not(linkage = "static"))]
use falco_plugin::{plugin, source_plugin};

#[cfg(not(linkage = "static"))]
plugin!(DummyPlugin);

#[cfg(not(linkage = "static"))]
source_plugin!(DummyPlugin);
