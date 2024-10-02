use falco_plugin::anyhow;
use falco_plugin::anyhow::{Context, Error};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::extract::EventInput;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;
use std::sync::atomic::{AtomicUsize, Ordering};

// we cant really get at the plugin state once we hand it off
// to the framework, so add some global state so we see
// what it's doing
thread_local! {
static GOT_EVENTS: AtomicUsize = const { AtomicUsize::new(0) };
static PARSED_EVENTS: AtomicUsize = const { AtomicUsize::new(0) };
}

struct DummyPlugin {
    event_num: usize,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        GOT_EVENTS.with(|ge| ge.store(0, Ordering::Relaxed));
        PARSED_EVENTS.with(|pe| pe.store(0, Ordering::Relaxed));
        Ok(Self { event_num: 0 })
    }
}

impl ParsePlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];

    fn parse_event(&mut self, event: &EventInput, _parse_input: &ParseInput) -> anyhow::Result<()> {
        GOT_EVENTS.with(|ge| ge.fetch_add(1, Ordering::Relaxed));
        let event = event
            .event()
            .context(format!("loading raw event {})", self.event_num))?;
        event
            .load_any()
            .context(format!("parsing event #{} {event:?}", self.event_num))?;

        self.event_num += 1;
        PARSED_EVENTS.with(|pe| pe.fetch_add(1, Ordering::Relaxed));

        Ok(())
    }
}

static_plugin!(PARSE_API = DummyPlugin);

#[cfg(test)]
#[cfg_attr(not(have_libsinsp), allow(dead_code))]
mod tests {
    use falco_plugin_tests::{
        init_plugin, instantiate_sinsp_tests, CapturingTestDriver, SavefileTestDriver, ScapStatus,
    };
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    fn open_capture_file<D: SavefileTestDriver>(driver: D) -> anyhow::Result<D::Capturing> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let scap_file = PathBuf::from(manifest_dir).join("tests/scap/kexec_x86.scap");
        let scap_file = CString::new(scap_file.as_os_str().as_bytes())?;

        driver.load_capture_file(scap_file.as_c_str())
    }

    fn test_capture_open<D: SavefileTestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(super::PARSE_API, c"").unwrap();
        open_capture_file(driver).unwrap();
    }

    fn test_count_events<D: SavefileTestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(super::PARSE_API, c"").unwrap();
        let mut driver = open_capture_file(driver).unwrap();

        let mut counter = 0;
        loop {
            match driver.next_event() {
                Ok(_) => {
                    counter += 1;
                }
                Err(ScapStatus::Eof) => break,
                Err(e) => panic!("{:?}", e),
            }
        }

        assert_eq!(counter, 523412);
    }

    fn test_with_plugin<D: SavefileTestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(super::PARSE_API, c"").unwrap();
        let mut driver = open_capture_file(driver).unwrap();

        let mut counter = 0;
        loop {
            match driver.next_event() {
                Ok(_) => {
                    counter += 1;
                }
                Err(ScapStatus::Eof) => break,
                Err(e) => panic!("{:?}", e),
            }
        }

        assert_eq!(counter, 523412);

        // for whatever reason, we're not getting all the events in the parse plugin,
        // but whatever we get, we should parse without errors
        let got_events = super::GOT_EVENTS.with(|e| e.load(Ordering::Relaxed));
        let parsed_events = super::PARSED_EVENTS.with(|e| e.load(Ordering::Relaxed));
        assert_eq!(got_events, parsed_events);
    }

    instantiate_sinsp_tests!(
        test_capture_open;
        test_count_events;
        test_with_plugin
    );
}
