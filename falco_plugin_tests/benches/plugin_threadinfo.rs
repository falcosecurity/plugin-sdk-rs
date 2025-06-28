use anyhow::Error;
use criterion::measurement::Measurement;
use criterion::{
    criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::parse::{EventInput, ParseInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::{import, TablesInput};
use falco_plugin_tests::plugin_collection::source::batched_empty_event::{
    BatchedEmptyEvent, BATCHED_EMPTY_EVENT,
};
use falco_plugin_tests::{init_plugin, CapturingTestDriver, PlatformData, TestDriver};
use std::ffi::CStr;
use std::sync::Arc;

const NUM_EVENTS: usize = 1000;

type Threadinfo = import::Entry<Arc<ThreadTableMetadata>>;
#[derive(import::TableMetadata)]
#[entry_type(Threadinfo)]
struct ThreadTableMetadata {
    tid: import::Field<i64, Threadinfo>,
    pid: import::Field<i64, Threadinfo>,
    #[custom]
    val: import::Field<i64, Threadinfo>,
}

pub struct ExtractThreadInfo {
    pid: i64,
    threads: import::Table<i64, Threadinfo>,
}

impl Plugin for ExtractThreadInfo {
    const NAME: &'static CStr = c"extract_threadinfo";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("No tables input provided"))?;
        let pid = std::process::id() as i64;
        let threads = input.get_table(c"threads")?;
        Ok(Self { pid, threads })
    }
}

impl ExtractThreadInfo {
    fn extract_pid(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let entry = self.threads.get_entry(req.table_reader, &self.pid)?;
        Ok(entry.get_pid(req.table_reader)? as u64)
    }

    fn extract_val(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let entry = self.threads.get_entry(req.table_reader, &self.pid)?;
        Ok(entry.get_val(req.table_reader)? as u64)
    }
}

impl ExtractPlugin for ExtractThreadInfo {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &[];
    type ExtractContext = ();

    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("thread.pid", &Self::extract_pid),
        field("thread.val", &Self::extract_val),
    ];
}

static_plugin!(EXTRACT_THREADINFO = ExtractThreadInfo);

pub struct ParseThreadInfoSetCustomField {
    pid: i64,
    threads: import::Table<i64, Threadinfo>,
}

impl Plugin for ParseThreadInfoSetCustomField {
    const NAME: &'static CStr = c"parse_threadinfo_set_custom_field";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("No tables input provided"))?;
        let pid = std::process::id() as i64;
        let threads = input.get_table(c"threads")?;
        Ok(Self { pid, threads })
    }
}

impl ParsePlugin for ParseThreadInfoSetCustomField {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &[];

    fn parse_event(&mut self, _event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()> {
        let entry = self.threads.get_entry(&parse_input.reader, &self.pid)?;
        entry.set_val(&parse_input.writer, &self.pid)?;

        Ok(())
    }
}

static_plugin!(PARSE_THREADINFO_SET_CUSTOM_FIELD = ParseThreadInfoSetCustomField);

#[cfg_attr(not(have_libsinsp), allow(unused))]
fn bench_plugin_threadinfo_tid<D: TestDriver, M: Measurement>(g: &mut BenchmarkGroup<M>) {
    let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
    let extract_plugin = driver.register_plugin(&EXTRACT_THREADINFO, c"").unwrap();
    driver
        .add_filterchecks(&extract_plugin, c"batched_empty_event")
        .unwrap();

    let mut driver = driver
        .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Enabled)
        .unwrap();
    let event = driver.next_event().unwrap();

    g.bench_with_input(
        BenchmarkId::new(D::NAME, "lookup_static_field"),
        &(),
        |b, _i| {
            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    match criterion::black_box(driver.extract_field(c"thread.pid", &event)) {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
}

#[cfg_attr(not(have_libsinsp), allow(unused))]
fn bench_plugin_threadinfo_missing_custom_field<D: TestDriver, M: Measurement>(
    g: &mut BenchmarkGroup<M>,
) {
    let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
    let extract_plugin = driver.register_plugin(&EXTRACT_THREADINFO, c"").unwrap();
    driver
        .add_filterchecks(&extract_plugin, c"batched_empty_event")
        .unwrap();

    let mut driver = driver
        .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Enabled)
        .unwrap();
    let event = driver.next_event().unwrap();

    g.bench_with_input(
        BenchmarkId::new(D::NAME, "lookup_missing_field"),
        &(),
        |b, _i| {
            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    let as_string = driver.extract_field(c"thread.val", &event);
                    match as_string {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
}

#[cfg_attr(not(have_libsinsp), allow(unused))]
fn bench_plugin_threadinfo_only_set_custom_field<D: TestDriver, M: Measurement>(
    g: &mut BenchmarkGroup<M>,
) {
    let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
    driver
        .register_plugin(&PARSE_THREADINFO_SET_CUSTOM_FIELD, c"")
        .unwrap();

    let mut driver = driver
        .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Enabled)
        .unwrap();

    g.bench_with_input(
        BenchmarkId::new(D::NAME, "only_set_custom_field"),
        &(),
        |b, _i| {
            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    match criterion::black_box(driver.next_event()) {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
}

#[cfg_attr(not(have_libsinsp), allow(unused))]
fn bench_plugin_threadinfo_custom_field<D: TestDriver, M: Measurement>(g: &mut BenchmarkGroup<M>) {
    let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
    driver
        .register_plugin(&PARSE_THREADINFO_SET_CUSTOM_FIELD, c"")
        .unwrap();
    let extract_plugin = driver.register_plugin(&EXTRACT_THREADINFO, c"").unwrap();
    driver
        .add_filterchecks(&extract_plugin, c"batched_empty_event")
        .unwrap();

    let mut driver = driver
        .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Enabled)
        .unwrap();
    let event = driver.next_event().unwrap();

    g.bench_with_input(
        BenchmarkId::new(D::NAME, "set_and_lookup_custom_field"),
        &(),
        |b, _i| {
            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    match criterion::black_box(driver.extract_field(c"thread.val", &event)) {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
}

fn plugin_threadinfo(c: &mut Criterion) {
    let mut g = c.benchmark_group("plugin_threadinfo");
    g.throughput(Throughput::Elements(NUM_EVENTS as u64));

    #[cfg(have_libsinsp)]
    {
        crate::bench_plugin_threadinfo_tid::<falco_plugin_tests::ffi::Driver, _>(&mut g);
        crate::bench_plugin_threadinfo_missing_custom_field::<falco_plugin_tests::ffi::Driver, _>(
            &mut g,
        );
        crate::bench_plugin_threadinfo_only_set_custom_field::<falco_plugin_tests::ffi::Driver, _>(
            &mut g,
        );
        crate::bench_plugin_threadinfo_custom_field::<falco_plugin_tests::ffi::Driver, _>(&mut g);
    }

    g.finish();
}

criterion_group!(benches, plugin_threadinfo);
criterion_main!(benches);
