use criterion::measurement::Measurement;
use criterion::{
    criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use falco_plugin::base::Plugin;
use falco_plugin_tests::plugin_collection::source::batched_empty_event::*;
use falco_plugin_tests::{init_plugin, CapturingTestDriver, PlatformData, TestDriver};
use std::hint::black_box;

const NUM_EVENTS: usize = 1000;

fn bench_plugin_source_batch_impl<D: TestDriver, M: Measurement>(g: &mut BenchmarkGroup<M>) {
    for (batch_size, batch_size_cstr) in [(1, c"1"), (10, c"10"), (100, c"100"), (1000, c"1000")] {
        g.bench_with_input(
            BenchmarkId::new(D::NAME, batch_size),
            batch_size_cstr,
            |b, s| {
                let (driver, _plugin) = init_plugin::<D>(&BATCHED_EMPTY_EVENT, s).unwrap();
                let mut driver = driver
                    .start_capture(
                        BatchedEmptyEvent::NAME,
                        batch_size_cstr,
                        PlatformData::Disabled,
                    )
                    .unwrap();
                b.iter(|| {
                    for _ in 0..NUM_EVENTS {
                        match black_box(driver.next_event()) {
                            Ok(_) => (),
                            Err(e) => panic!("Unexpected error: {e}"),
                        }
                    }
                });
            },
        );
    }
}

fn plugin_source_batch(c: &mut Criterion) {
    let mut g = c.benchmark_group("plugin_source_batch");
    g.throughput(Throughput::Elements(NUM_EVENTS as u64));

    bench_plugin_source_batch_impl::<falco_plugin_tests::native::Driver, _>(&mut g);
    #[cfg(have_libsinsp)]
    bench_plugin_source_batch_impl::<falco_plugin_tests::ffi::Driver, _>(&mut g);

    g.finish();
}

criterion_group!(benches, plugin_source_batch);
criterion_main!(benches);
