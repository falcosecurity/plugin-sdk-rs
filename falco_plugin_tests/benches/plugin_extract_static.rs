use anyhow::Error;
use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, Throughput};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use falco_plugin_tests::plugin_collection::source::batched_empty_event::{
    BatchedEmptyEvent, BATCHED_EMPTY_EVENT,
};
use falco_plugin_tests::{init_plugin, CapturingTestDriver, PlatformData, TestDriver};
use std::ffi::CStr;
use std::hint::black_box;

const NUM_EVENTS: usize = 1000;

struct ExtractStaticPlugin;

impl Plugin for ExtractStaticPlugin {
    const NAME: &'static CStr = c"extract_static";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(ExtractStaticPlugin)
    }
}

impl ExtractStaticPlugin {
    fn extract_static(&mut self, _req: ExtractRequest<Self>) -> Result<u64, Error> {
        Ok(5)
    }
}

impl ExtractPlugin for ExtractStaticPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &[];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("static.field", &Self::extract_static)];
}

static_plugin!(EXTRACT_STATIC_PLUGIN = ExtractStaticPlugin);

fn plugin_extract_static_impl<D: TestDriver, M: Measurement>(g: &mut BenchmarkGroup<M>) {
    g.bench_function(D::NAME, |b| {
        let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
        let extract_plugin = driver.register_plugin(&EXTRACT_STATIC_PLUGIN, c"").unwrap();
        driver
            .add_filterchecks(&extract_plugin, c"batched_empty_event")
            .unwrap();
        let mut driver = driver
            .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Disabled)
            .unwrap();
        let event = driver.next_event().unwrap();

        b.iter(|| {
            for _ in 0..NUM_EVENTS {
                match black_box(driver.extract_field(c"static.field", &event)) {
                    Ok(_) => (),
                    Err(e) => panic!("Unexpected error: {e}"),
                }
            }
        });
    });
}

fn plugin_extract_static(c: &mut Criterion) {
    let mut g = c.benchmark_group("plugin_extract_static");
    g.throughput(Throughput::Elements(NUM_EVENTS as u64));

    plugin_extract_static_impl::<falco_plugin_tests::native::Driver, _>(&mut g);
    #[cfg(have_libsinsp)]
    plugin_extract_static_impl::<falco_plugin_tests::ffi::Driver, _>(&mut g);

    g.finish();
}

criterion_group!(benches, plugin_extract_static);
criterion_main!(benches);
