use falco_plugin::anyhow;
use falco_plugin::anyhow::{Context, Error};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::{EventType, PPME_SYSCALL_READ_E};
use falco_plugin::event::events::Event;
use falco_plugin::event::fields::types::PT_FD;
use falco_plugin::extract::EventInput;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::import::{Entry, Field, Table, TableMetadata};
use falco_plugin::tables::TablesInput;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

type Fd = Entry<Arc<FdMetadata>>;
type FdTable = Table<i64, Fd>;

#[derive(TableMetadata)]
#[entry_type(Fd)]
struct FdMetadata {
    fd: Field<i64, Fd>,

    #[name(c"type")]
    fd_type: Field<u8, Fd>,
}

type Thread = Entry<Arc<ThreadMetadata>>;
type ThreadTable = Table<i64, Thread>;

#[derive(TableMetadata)]
#[entry_type(Thread)]
struct ThreadMetadata {
    comm: Field<CStr, Thread>,
    file_descriptors: Field<FdTable, Thread>,

    #[custom]
    num_events: Field<u64, Thread>,
}

thread_local! {
static TEST_DONE: AtomicBool = AtomicBool::new(false);
}

struct DummyPlugin {
    threads: ThreadTable,
    event_num: usize,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        TEST_DONE.with(|flag| flag.store(false, Ordering::Relaxed));

        let Some(input) = input else {
            anyhow::bail!("Did not get tables input")
        };

        let threads = input.get_table(c"threads")?;

        Ok(Self {
            threads,
            event_num: 0,
        })
    }
}

impl ParsePlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];

    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()> {
        self.event_num += 1;

        // matching against a random(ish) event in kexec_x86.scap
        if self.event_num == 1452 {
            let event = event
                .event()
                .context(format!("loading raw event {})", self.event_num))?;
            let event: Event<PPME_SYSCALL_READ_E> = event
                .load()
                .context(format!("parsing event #{} {event:?}", self.event_num))?;

            let Some(PT_FD(event_fd)) = event.params.fd else {
                anyhow::bail!("event did not have the fd param set");
            };

            if event_fd != 16 {
                anyhow::bail!("event param mismatch, expected fd=16, got {}", event_fd);
            }

            let r = &parse_input.reader;

            let tid = event.metadata.tid;
            let thread = self.threads.get_entry(r, &tid)?;

            let comm = thread.get_comm(r)?;
            if comm.to_bytes() != b"node" {
                anyhow::bail!("comm mismatch, expected \"node\", got {:?}", comm);
            }

            let event_fd_entry = thread.get_file_descriptors_by_key(r, &event_fd)?;
            let fd_type = event_fd_entry.get_fd_type(r)?;
            if fd_type != 9 {
                anyhow::bail!("fd type mismatch in direct lookup, got {}", fd_type);
            }

            let mut fd_map = BTreeMap::new();
            let fds = thread.get_file_descriptors(&parse_input.reader)?;
            fds.iter_entries_mut(&parse_input.reader, |fd| {
                let Ok(fd_num) = fd.get_fd(&parse_input.reader) else {
                    return ControlFlow::Continue(());
                };
                let Ok(fd_type) = fd.get_fd_type(&parse_input.reader) else {
                    return ControlFlow::Continue(());
                };

                fd_map.insert(fd_num, fd_type);
                ControlFlow::Continue(())
            })?;

            if fd_map.len() != 33 {
                anyhow::bail!("fd table length mismatch, got {}", fd_map.len());
            }

            let fd_type = fd_map.get(&event_fd);
            if fd_type != Some(&9) {
                anyhow::bail!(
                    "fd type mismatch in iter_entries_mut map, got {:?}",
                    fd_type
                )
            }

            TEST_DONE.with(|flag| flag.store(true, Ordering::Relaxed));
        }

        Ok(())
    }
}

static_plugin!(PARSE_API = DummyPlugin);

#[cfg(test)]
#[cfg_attr(not(have_libsinsp), allow(dead_code))]
mod tests {
    use crate::TEST_DONE;
    use falco_plugin_tests::{
        init_plugin, instantiate_sinsp_tests, CapturingTestDriver, SavefileTestDriver, ScapStatus,
    };
    use std::ffi::CString;
    use std::sync::atomic::Ordering;
    use typed_path::UnixPathBuf;

    fn open_capture_file<D: SavefileTestDriver>(driver: D) -> anyhow::Result<D::Capturing> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let scap_file = UnixPathBuf::from(manifest_dir).join("tests/scap/kexec_x86.scap");
        let scap_file = CString::new(scap_file.as_bytes())?;

        driver.load_capture_file(scap_file.as_c_str())
    }

    fn test_with_plugin<D: SavefileTestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(&super::PARSE_API, c"").unwrap();
        let mut driver = open_capture_file(driver).unwrap();

        loop {
            match driver.next_event() {
                Ok(_) => continue,
                Err(ScapStatus::Eof) => break,
                Err(e) => panic!("{:?}", e),
            }
        }

        assert!(TEST_DONE.with(|flag| flag.load(Ordering::Relaxed)));
    }

    instantiate_sinsp_tests!(test_with_plugin);
}
