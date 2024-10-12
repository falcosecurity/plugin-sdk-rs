use crate::events::types::{owned, AnyEvent};
use crate::events::types::PPME_SYSCALL_READ_E;
use crate::events::{Event, EventMetadata};
use crate::types::Fd;

#[test]
fn test_serde_read_e() {
    let event = PPME_SYSCALL_READ_E {
        fd: Some(Fd(0)),
        size: Some(120),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(json, r#"{"fd":0,"size":120}"#);

    let event2: owned::PPME_SYSCALL_READ_E = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&event2).unwrap();

    assert_eq!(json, json2);
}

#[test]
fn test_serde_event_read_e() {
    let event = Event {
        metadata: EventMetadata {
            ts: 100_000_000_000,
            tid: 10,
        },
        params: AnyEvent::SYSCALL_READ_E(PPME_SYSCALL_READ_E {
            fd: Some(Fd(0)),
            size: Some(120),
        }),
    };

    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(
        json,
        r#"{"ts":100000000000,"tid":10,"SYSCALL_READ_E":{"fd":0,"size":120}}"#
    );

    let event2: Event<owned::AnyEvent> = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&event2).unwrap();

    assert_eq!(json, json2);
}
