use anyhow::Error;
use criterion::measurement::Measurement;
use criterion::{
    criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::source::EventInput;
use falco_plugin::static_plugin;
use falco_plugin::tables::{export, import, TablesInput};
use falco_plugin_tests::plugin_collection::source::batched_empty_event::{
    BatchedEmptyEvent, BATCHED_EMPTY_EVENT,
};
use falco_plugin_tests::{init_plugin, CapturingTestDriver, PlatformData, TestDriver};
use std::ffi::CStr;
use std::sync::Arc;

const NUM_EVENTS: usize = 1000;

#[derive(export::Entry)]
struct ExportedCustomEntry {
    val: export::Public<i64>,
}

type ImportedCustomEntry = import::Entry<Arc<ImportedCustomMetadata>>;

#[derive(import::TableMetadata)]
#[entry_type(ImportedCustomEntry)]
struct ImportedCustomMetadata {
    val: import::Field<i64, ImportedCustomEntry>,

    #[custom]
    val2: import::Field<i64, ImportedCustomEntry>,
}

struct CustomTableApi {
    #[allow(unused)]
    exported_custom_table: Box<export::Table<i64, ExportedCustomEntry>>,
    imported_custom_table: import::Table<i64, ImportedCustomEntry>,

    insert_val2_on_parse: bool,
}

impl Plugin for CustomTableApi {
    const NAME: &'static CStr = c"custom_table_api";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = String;

    fn new(input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("No tables input provided"))?;
        let custom_table: export::Table<i64, ExportedCustomEntry> =
            export::Table::new(c"custom_table")?;
        let exported_custom_table = input.add_table(custom_table)?;
        let imported_custom_table = input.get_table(c"custom_table")?;

        let insert_val2_on_parse = config == "insert_val2_on_parse";

        Ok(Self {
            exported_custom_table,
            imported_custom_table,
            insert_val2_on_parse,
        })
    }
}

impl CustomTableApi {
    fn extract_val_api(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let key = req.event.event_number() as i64;
        let entry = self
            .imported_custom_table
            .get_entry(req.table_reader, &key)?;
        Ok(entry.get_val(req.table_reader)? as u64)
    }

    fn extract_val2_api(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let key = req.event.event_number() as i64;
        let entry = self
            .imported_custom_table
            .get_entry(req.table_reader, &key)?;
        Ok(entry.get_val2(req.table_reader)? as u64)
    }
}

impl ExtractPlugin for CustomTableApi {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &[];
    type ExtractContext = ();

    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("thread.val_api", &Self::extract_val_api),
        field("thread.val2_api", &Self::extract_val2_api),
    ];
}

impl ParsePlugin for CustomTableApi {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &[];

    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> anyhow::Result<()> {
        let key = event.event_number() as i64;
        let entry = self
            .imported_custom_table
            .create_entry(&parse_input.writer)?;
        entry.set_val(&parse_input.writer, &key)?;
        if self.insert_val2_on_parse {
            entry.set_val2(&parse_input.writer, &key)?;
        }
        self.imported_custom_table
            .insert(&parse_input.reader, &parse_input.writer, &key, entry)?;

        Ok(())
    }
}

static_plugin!(CUSTOM_TABLE_API = CustomTableApi);

struct CustomTableDirect {
    #[allow(unused)]
    exported_custom_table: Box<export::Table<i64, ExportedCustomEntry>>,
}

impl Plugin for CustomTableDirect {
    const NAME: &'static CStr = c"custom_table_api";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("No tables input provided"))?;
        let custom_table: export::Table<i64, ExportedCustomEntry> =
            export::Table::new(c"custom_table")?;
        let exported_custom_table = input.add_table(custom_table)?;

        Ok(Self {
            exported_custom_table,
        })
    }
}

impl CustomTableDirect {
    fn extract_val_api(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let key = req.event.event_number() as i64;
        let entry = self
            .exported_custom_table
            .lookup(&key)
            .expect("Failed to lookup entry");
        Ok(*entry.val as u64)
    }
}

impl ExtractPlugin for CustomTableDirect {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &[];
    type ExtractContext = ();

    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("thread.val_direct", &Self::extract_val_api)];
}

impl ParsePlugin for CustomTableDirect {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &[];

    fn parse_event(&mut self, event: &EventInput, _parse_input: &ParseInput) -> anyhow::Result<()> {
        let key = event.event_number() as i64;
        let mut entry = self.exported_custom_table.create_entry()?;
        *entry.val = key;
        self.exported_custom_table.insert(&key, entry);

        Ok(())
    }
}

static_plugin!(CUSTOM_TABLE_DIRECT = CustomTableDirect);

fn bench_plugin_custom_table_extract_only_impl<D: TestDriver, M: Measurement>(
    g: &mut BenchmarkGroup<M>,
) {
    g.bench_with_input(
        BenchmarkId::new(D::NAME, "static_field_direct"),
        &(),
        |b, _input| {
            let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
            let extract_plugin = driver.register_plugin(&CUSTOM_TABLE_DIRECT, c"").unwrap();
            driver
                .add_filterchecks(&extract_plugin, c"batched_empty_event")
                .unwrap();
            let mut driver = driver
                .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Disabled)
                .unwrap();
            let event = driver.next_event().unwrap();

            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    match criterion::black_box(driver.extract_field(c"thread.val_direct", &event)) {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
    g.bench_with_input(
        BenchmarkId::new(D::NAME, "static_field_api"),
        &(),
        |b, _input| {
            let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
            let extract_plugin = driver.register_plugin(&CUSTOM_TABLE_API, c"").unwrap();
            driver
                .add_filterchecks(&extract_plugin, c"batched_empty_event")
                .unwrap();
            let mut driver = driver
                .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Disabled)
                .unwrap();
            let event = driver.next_event().unwrap();

            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    match criterion::black_box(driver.extract_field(c"thread.val_api", &event)) {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
    g.bench_with_input(
        BenchmarkId::new(D::NAME, "dynamic_field_api"),
        &(),
        |b, _input| {
            let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
            let extract_plugin = driver
                .register_plugin(&CUSTOM_TABLE_API, c"insert_val2_on_parse")
                .unwrap();
            driver
                .add_filterchecks(&extract_plugin, c"batched_empty_event")
                .unwrap();
            let mut driver = driver
                .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Disabled)
                .unwrap();
            let event = driver.next_event().unwrap();

            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    match criterion::black_box(driver.extract_field(c"thread.val2_api", &event)) {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
}

fn bench_plugin_custom_table_extract_only(c: &mut Criterion) {
    let mut g = c.benchmark_group("plugin_custom_table_extract_only");
    g.throughput(Throughput::Elements(NUM_EVENTS as u64));

    bench_plugin_custom_table_extract_only_impl::<falco_plugin_tests::native::Driver, _>(&mut g);
    #[cfg(have_libsinsp)]
    bench_plugin_custom_table_extract_only_impl::<falco_plugin_tests::ffi::Driver, _>(&mut g);

    g.finish();
}

fn bench_plugin_custom_table_insert_and_extract_impl<D: TestDriver, M: Measurement>(
    g: &mut BenchmarkGroup<M>,
) {
    g.bench_with_input(
        BenchmarkId::new(D::NAME, "static_field_direct"),
        &(),
        |b, _input| {
            let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
            let extract_plugin = driver.register_plugin(&CUSTOM_TABLE_DIRECT, c"").unwrap();
            driver
                .add_filterchecks(&extract_plugin, c"batched_empty_event")
                .unwrap();
            let mut driver = driver
                .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Disabled)
                .unwrap();

            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    let event = driver.next_event().unwrap();
                    let as_string =
                        criterion::black_box(driver.extract_field(c"thread.val_direct", &event));
                    match as_string {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
    g.bench_with_input(
        BenchmarkId::new(D::NAME, "static_field_api"),
        &(),
        |b, _input| {
            let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
            let extract_plugin = driver.register_plugin(&CUSTOM_TABLE_API, c"").unwrap();
            driver
                .add_filterchecks(&extract_plugin, c"batched_empty_event")
                .unwrap();
            let mut driver = driver
                .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Disabled)
                .unwrap();

            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    let event = driver.next_event().unwrap();
                    let as_string =
                        criterion::black_box(driver.extract_field(c"thread.val_api", &event));
                    match as_string {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
    g.bench_with_input(
        BenchmarkId::new(D::NAME, "dynamic_field_api"),
        &(),
        |b, _input| {
            let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
            let extract_plugin = driver
                .register_plugin(&CUSTOM_TABLE_API, c"insert_val2_on_parse")
                .unwrap();
            driver
                .add_filterchecks(&extract_plugin, c"batched_empty_event")
                .unwrap();
            let mut driver = driver
                .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Disabled)
                .unwrap();

            b.iter(|| {
                for _ in 0..NUM_EVENTS {
                    let event = driver.next_event().unwrap();
                    let as_string =
                        criterion::black_box(driver.extract_field(c"thread.val2_api", &event));
                    match as_string {
                        Ok(_) => (),
                        Err(e) => panic!("Unexpected error: {e}"),
                    }
                }
            });
        },
    );
}

fn bench_plugin_custom_table_insert_and_extract(c: &mut Criterion) {
    let mut g = c.benchmark_group("plugin_custom_table_insert_and_extract");
    g.throughput(Throughput::Elements(NUM_EVENTS as u64));

    bench_plugin_custom_table_insert_and_extract_impl::<falco_plugin_tests::native::Driver, _>(
        &mut g,
    );
    #[cfg(have_libsinsp)]
    bench_plugin_custom_table_insert_and_extract_impl::<falco_plugin_tests::ffi::Driver, _>(&mut g);

    g.finish();
}

criterion_group!(
    benches,
    bench_plugin_custom_table_extract_only,
    bench_plugin_custom_table_insert_and_extract
);
criterion_main!(benches);
