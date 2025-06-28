use anyhow::Error;
use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, Throughput};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::parse::{EventInput, ParsePlugin};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use falco_plugin_tests::plugin_collection::source::batched_empty_event::{
    BatchedEmptyEvent, BATCHED_EMPTY_EVENT,
};
use falco_plugin_tests::{init_plugin, CapturingTestDriver, PlatformData, TestDriver};
use std::ffi::CStr;
use std::hint::black_box;

struct NoopParsePlugin;

impl Plugin for NoopParsePlugin {
    const NAME: &'static CStr = c"noop_parse";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(NoopParsePlugin)
    }
}

impl ParsePlugin for NoopParsePlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &[];

    fn parse_event(
        &mut self,
        _event: &EventInput,
        _parse_input: &falco_plugin::parse::ParseInput,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

static_plugin!(pub NOOP_PARSE_PLUGIN = NoopParsePlugin);

const NUM_EVENTS: usize = 1000;

fn bench_plugin_source_parse_noop_impl<D: TestDriver, M: Measurement>(g: &mut BenchmarkGroup<M>) {
    let (mut driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, c"1").unwrap();
    driver.register_plugin(&NOOP_PARSE_PLUGIN, c"").unwrap();
    let mut driver = driver
        .start_capture(BatchedEmptyEvent::NAME, c"1", PlatformData::Disabled)
        .unwrap();
    g.bench_function(D::NAME, |b| {
        b.iter(|| {
            for _ in 0..NUM_EVENTS {
                match black_box(driver.next_event()) {
                    Ok(_) => (),
                    Err(e) => panic!("Unexpected error: {e}"),
                }
            }
        });
    });
}

fn plugin_source_parse_noop(c: &mut Criterion) {
    let mut g = c.benchmark_group("plugin_source_parse_noop");
    g.throughput(Throughput::Elements(NUM_EVENTS as u64));

    bench_plugin_source_parse_noop_impl::<falco_plugin_tests::native::Driver, _>(&mut g);
    #[cfg(have_libsinsp)]
    bench_plugin_source_parse_noop_impl::<falco_plugin_tests::ffi::Driver, _>(&mut g);

    g.finish();
}

criterion_group!(benches, plugin_source_parse_noop);
criterion_main!(benches);
