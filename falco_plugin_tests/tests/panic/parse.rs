use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::RawEvent;
use falco_plugin::extract::EventInput;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use falco_plugin_tests::plugin_collection::source::countdown::{
    CountdownPlugin, COUNTDOWN_PLUGIN_API,
};
use falco_plugin_tests::{
    init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, TestDriver,
};
use std::ffi::CStr;

struct ParseablePlugin;

impl Plugin for ParseablePlugin {
    const NAME: &'static CStr = c"parseable";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"panics in parse_event";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

impl ParsePlugin for ParseablePlugin {
    type Event<'a> = RawEvent<'a>;

    fn parse_event(
        &mut self,
        _event: &EventInput<Self::Event<'_>>,
        _parse_input: &ParseInput,
    ) -> Result<(), Error> {
        panic!("parse panic")
    }
}

static_plugin!(PARSEABLE_PLUGIN_API = ParseablePlugin);

fn test_parse_panic<D: TestDriver>() {
    let (mut driver, _source_plugin) = init_plugin::<D>(
        &COUNTDOWN_PLUGIN_API,
        cr#"{"remaining": 1, "batch_size": 1}"#,
    )
    .unwrap();
    driver.register_plugin(&PARSEABLE_PLUGIN_API, c"").unwrap();

    let mut driver = driver
        .start_capture(CountdownPlugin::NAME, c"", PlatformData::Disabled)
        .unwrap();

    // the Rust driver will propagate the error while sinsp will silently
    // ignore it and return the event, so we're just checking here that
    // we catch the panic.
    driver.next_event().ok();
}

instantiate_tests!(test_parse_panic);
