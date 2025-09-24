use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::RawEvent;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use falco_plugin_tests::plugin_collection::source::countdown::{
    CountdownPlugin, COUNTDOWN_PLUGIN_API,
};
use falco_plugin_tests::{
    init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, TestDriver,
};
use std::ffi::{CStr, CString};

struct ExtractablePlugin;

impl Plugin for ExtractablePlugin {
    const NAME: &'static CStr = c"extractable";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"panics in extract_fields";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

impl ExtractablePlugin {
    fn extract_panic(&mut self, _req: ExtractRequest<Self>) -> Result<CString, Error> {
        panic!("extract panic")
    }
}

impl ExtractPlugin for ExtractablePlugin {
    type Event<'a> = RawEvent<'a>;
    type ExtractContext = ();

    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("extractable.panicking", &Self::extract_panic)];
}

static_plugin!(EXTRACTABLE_PLUGIN_API = ExtractablePlugin);

fn test_extract_panic<D: TestDriver>() {
    let (mut driver, _source_plugin) = init_plugin::<D>(
        &COUNTDOWN_PLUGIN_API,
        cr#"{"remaining": 1, "batch_size": 1}"#,
    )
    .unwrap();
    let extract_plugin = driver
        .register_plugin(&EXTRACTABLE_PLUGIN_API, c"")
        .unwrap();
    driver
        .add_filterchecks(&extract_plugin, c"countdown")
        .unwrap();

    let mut driver = driver
        .start_capture(CountdownPlugin::NAME, c"", PlatformData::Disabled)
        .unwrap();

    let event = driver.next_event().unwrap();
    assert!(driver
        .event_field_as_string(c"extractable.panicking", &event)
        .is_err());
}

instantiate_tests!(test_extract_panic);
