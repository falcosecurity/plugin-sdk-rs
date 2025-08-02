use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use falco_plugin::event::events::types::AnyEvent;
use falco_plugin::event::events::{Event, EventToBytes, RawEvent};
use std::hint::black_box;
use std::path::PathBuf;

fn load(events: &[u8]) -> Vec<Event<AnyEvent<'_>>> {
    RawEvent::scan(events)
        .map(|event| event.unwrap().load_any().unwrap())
        .collect()
}

fn test_parse(events: &[u8]) {
    RawEvent::scan(events)
        .map(|event| event.unwrap().load_any().unwrap())
        .for_each(|event| {
            black_box(event);
        });
}

fn test_dump(events: &[Event<AnyEvent>], out: &mut Vec<u8>) {
    out.clear();
    for event in events {
        event.write(&mut *out).unwrap();
    }
}

fn bench_parse(c: &mut Criterion) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let events_file = PathBuf::from(manifest_dir).join("tests/scap/kexec_x86.raw");
    let events = std::fs::read(&events_file).unwrap();

    let mut g = c.benchmark_group("event_parse_all");
    g.throughput(Throughput::Bytes(events.len() as u64));
    g.bench_function("event_parse_all", |b| {
        b.iter(|| test_parse(black_box(&events)))
    });
}

fn bench_dump(c: &mut Criterion) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let events_file = PathBuf::from(manifest_dir).join("tests/scap/kexec_x86.raw");
    let events = std::fs::read(&events_file).unwrap();
    let events = load(&events);
    let mut out = Vec::new();

    let mut g = c.benchmark_group("event_dump_all");
    g.throughput(Throughput::Elements(events.len() as u64));
    g.bench_function("event_dump_all", |b| {
        b.iter(|| test_dump(black_box(events.as_slice()), &mut out))
    });
}

criterion_group!(benches, bench_parse, bench_dump);
criterion_main!(benches);
