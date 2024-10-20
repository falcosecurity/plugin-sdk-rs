use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin};
use std::ffi::CStr;

struct DummyPlugin;

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy no-op plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = String;

    fn new(_input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self, Error> {
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

static_plugin!(
    #[no_capabilities]
    DUMMY_PLUGIN_API = DummyPlugin
);

#[cfg(test)]
mod tests {
    use falco_plugin_tests::{init_plugin, instantiate_tests, TestDriver};

    fn test_dummy_init<D: TestDriver>() {
        let res = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"testing");

        // Exception { what: "cannot load plugin with custom vtable: plugin does not implement any capability" }
        assert!(res.is_err())
    }

    instantiate_tests!(test_dummy_init);
}
