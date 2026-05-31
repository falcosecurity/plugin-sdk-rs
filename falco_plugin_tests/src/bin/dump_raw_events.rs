use anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::{EventToBytes, RawEvent};
use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;
use std::fs::File;

struct DumperPlugin(File);

impl Plugin for DumperPlugin {
    const NAME: &'static CStr = c"dumper_test_plugin";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dump all events as raw bytes to an output file";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/plugin-sdk-rs";
    type ConfigType = String;

    fn new(_input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self, Error> {
        let output = std::fs::File::create(config)?;
        Ok(DumperPlugin(output))
    }
}

impl ParsePlugin for DumperPlugin {
    type Event<'a> = RawEvent<'a>;

    fn parse_event(
        &mut self,
        event: &EventInput<Self::Event<'_>>,
        _parse_input: &ParseInput,
    ) -> anyhow::Result<()> {
        let event = event.event()?;
        Ok(event.write(&mut self.0)?)
    }
}

static_plugin!(DUMPER_PLUGIN = DumperPlugin);

#[cfg(any(not(have_libsinsp), miri))]
fn main() {
    panic!("libsinsp not available");
}

#[cfg(all(have_libsinsp, not(miri)))]
fn main() {
    use falco_plugin_tests::CapturingTestDriver;
    use falco_plugin_tests::SavefileTestDriver;
    use falco_plugin_tests::ScapStatus;
    use falco_plugin_tests::TestDriver;
    use std::ffi::CString;

    let scap_path = std::env::args().nth(1).unwrap();
    let scap_path = CString::new(scap_path).unwrap();

    let output_path = std::env::args().nth(2).unwrap();
    let output_path = CString::new(output_path).unwrap();

    let mut driver = falco_plugin_tests::ffi::Driver::new().unwrap();
    driver
        .register_plugin(&DUMPER_PLUGIN, output_path.as_c_str())
        .unwrap();
    let mut driver = driver.load_capture_file(scap_path.as_c_str()).unwrap();

    loop {
        match driver.next_event() {
            Ok(_) => continue,
            Err(ScapStatus::Eof) => break,
            Err(e) => panic!("{e:?}"),
        }
    }
}
