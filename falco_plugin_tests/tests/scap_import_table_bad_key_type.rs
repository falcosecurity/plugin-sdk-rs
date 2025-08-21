use falco_plugin::anyhow;
use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::extract::EventInput;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::import::{Entry, Field, Table, TableMetadata};
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;
use std::sync::Arc;

type Fd = Entry<Arc<FdMetadata>>;
type FdTable = Table<i32, Fd>; // the actual key type is i32, so we expect an error

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

struct DummyPlugin {
    #[allow(dead_code)]
    threads: ThreadTable,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let Some(input) = input else {
            anyhow::bail!("Did not get tables input")
        };

        let threads = input.get_table(c"threads")?;

        Ok(Self { threads })
    }
}

impl ParsePlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];

    fn parse_event(
        &mut self,
        _event: &EventInput,
        _parse_input: &ParseInput,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

static_plugin!(PARSE_API = DummyPlugin);

#[cfg(test)]
#[cfg_attr(not(have_libsinsp), allow(dead_code))]
mod tests {
    use falco_plugin_tests::{init_plugin, instantiate_sinsp_tests, TestDriver};

    fn test_with_plugin<D: TestDriver>() {
        init_plugin::<D>(&super::PARSE_API, c"").unwrap_err();
    }

    instantiate_sinsp_tests!(test_with_plugin);
}
