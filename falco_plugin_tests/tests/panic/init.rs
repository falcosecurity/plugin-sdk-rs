use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::RawEvent;
use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use falco_plugin_tests::{init_plugin, instantiate_tests, TestDriver};
use std::ffi::CStr;

struct InitPlugin;

impl Plugin for InitPlugin {
    const NAME: &'static CStr = c"init_fails";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"panics in Plugin::new";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        panic!("new panic")
    }
}

impl ParsePlugin for InitPlugin {
    type Event<'a> = RawEvent<'a>;

    fn parse_event(
        &mut self,
        _event: &EventInput<Self::Event<'_>>,
        _parse_input: &ParseInput,
    ) -> Result<(), Error> {
        Ok(())
    }
}

static_plugin!(INIT_PLUGIN_API = InitPlugin);

fn test_init_panic<D: TestDriver>() {
    let res = init_plugin::<D>(&INIT_PLUGIN_API, c"");
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("new panic"));
}

instantiate_tests!(test_init_panic);
