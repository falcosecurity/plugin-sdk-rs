use anyhow::Error;
use falco_plugin::async_event::{AsyncEventPlugin, AsyncHandler, BackgroundTask};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType::{GENERIC_E, SYSCALL_EXECVE_8_E};
use falco_plugin::event::events::types::{EventType, PPME_GENERIC_E};
use falco_plugin::event::events::{Event, EventMetadata};
use falco_plugin::event::fields::types::PT_SYSCALLID;
use falco_plugin::extract::EventInput;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::source::{EventBatch, SourcePlugin, SourcePluginInstance};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use falco_plugin::tables::{export, import};
use std::ffi::{CStr, CString};
use std::ops::ControlFlow::Continue;
use std::panic;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(export::Entry)]
struct TableEntry {
    num: export::Public<u64>,
}

struct DummyAsyncPlugin {
    task: Arc<BackgroundTask>,
    thread: Option<JoinHandle<Result<(), Error>>>,

    table: Box<export::Table<u64, TableEntry>>,
}

impl Plugin for DummyAsyncPlugin {
    const NAME: &'static CStr = c"dummy_async";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy async plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let Some(input) = input else {
            anyhow::bail!("Did not get tables input")
        };

        let table = input.add_table(export::Table::<u64, TableEntry>::new(c"table")?)?;

        Ok(Self {
            task: Arc::new(BackgroundTask::default()),
            thread: None,

            table,
        })
    }
}

impl ParsePlugin for DummyAsyncPlugin {
    const EVENT_TYPES: &'static [EventType] = &[SYSCALL_EXECVE_8_E]; // a dummy event that will never happen
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];

    fn parse_event(
        &mut self,
        _event: &EventInput,
        _parse_input: &ParseInput,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

impl AsyncEventPlugin for DummyAsyncPlugin {
    const ASYNC_EVENTS: &'static [&'static str] = &["dummy_async"];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];

    fn start_async(&mut self, _handler: AsyncHandler) -> Result<(), Error> {
        if self.thread.is_some() {
            self.stop_async()?;
        }

        let data = self.table.data();
        let create_entry_fn = self.table.create_entry_fn();
        let mut counter = 0;

        self.thread = Some(self.task.spawn(Duration::from_millis(100), move || {
            let entry = create_entry_fn().unwrap();
            *entry.write().num = counter;
            data.write().insert(counter, entry);

            counter += 1;
            Ok(())
        })?);

        Ok(())
    }

    fn stop_async(&mut self) -> Result<(), Error> {
        dbg!("requesting shutdown");
        self.task.request_stop_and_notify()?;

        let Some(handle) = self.thread.take() else {
            return Ok(());
        };

        match handle.join() {
            Ok(res) => res,
            Err(e) => panic::resume_unwind(e),
        }
    }
}

type ImportedTable = import::Table<u64, ImportedTableEntry>;
type ImportedTableEntry = import::Entry<Arc<ImportedTableMetadata>>;

#[derive(import::TableMetadata)]
#[entry_type(ImportedTableEntry)]
struct ImportedTableMetadata {
    num: import::Field<u64, ImportedTableEntry>,
}

struct DummyPlugin {
    imported_table: ImportedTable,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy no-op plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        log::set_max_level(log::LevelFilter::Trace);
        let Some(input) = input else {
            anyhow::bail!("Did not get tables input");
        };

        let imported_table = input.get_table(c"table")?;

        Ok(Self { imported_table })
    }

    fn set_config(&mut self, _config: Self::ConfigType) -> Result<(), Error> {
        Ok(())
    }
}

static ALL_DONE: AtomicBool = AtomicBool::new(false);

impl ParsePlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[GENERIC_E];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];

    fn parse_event(&mut self, _event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()> {
        log::info!("got event");
        let mut counter = 0;
        self.imported_table
            .iter_entries_mut(&parse_input.reader, |e| {
                let num = e.get_num(&parse_input.reader).unwrap();
                log::info!("num = {num}");
                assert_eq!(num, counter);
                counter += 1;
                Continue(())
            })?;

        ALL_DONE.store(true, std::sync::atomic::Ordering::Relaxed);

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
        std::thread::sleep(Duration::from_millis(1100));
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

static_plugin!(DUMMY_PLUGIN = DummyPlugin);
static_plugin!(DUMMY_ASYNC_PLUGIN = DummyAsyncPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{
        init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, TestDriver,
    };

    fn test_async<D: TestDriver>() {
        let (mut driver, _plugin) = init_plugin::<D>(&super::DUMMY_ASYNC_PLUGIN, c"").unwrap();
        driver.register_plugin(&super::DUMMY_PLUGIN, c"").unwrap();
        let mut driver = driver
            .start_capture(super::DummyPlugin::NAME, c"", PlatformData::Disabled)
            .unwrap();

        driver.next_event().unwrap();

        assert!(super::ALL_DONE.load(std::sync::atomic::Ordering::Relaxed));
    }

    instantiate_tests!(test_async);
}
