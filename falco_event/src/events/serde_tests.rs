use crate::events::types::{owned, AnyEvent, PPME_SYSCALL_READ_X};
use crate::events::types::{PPME_SYSCALL_GETCWD_X, PPME_SYSCALL_READ_E};
use crate::events::{Event, EventMetadata};
use crate::types::{Fd, SyscallResult};

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

#[test]
fn test_serde_read_x() {
    let event = PPME_SYSCALL_READ_X {
        res: Some(SyscallResult(5)),
        data: Some(b"hello".as_slice()),
        fd: Some(Fd(0)),
        size: Some(10),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(json, r#"{"res":5,"data":"hello","fd":0,"size":10}"#);

    let event2: owned::PPME_SYSCALL_READ_X = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&event2).unwrap();

    assert_eq!(json, json2);
}

#[test]
fn test_serde_read_x_bin() {
    let json = r#"{"res":5,"data":[255,254,253,252,251]}"#;

    let event2: owned::PPME_SYSCALL_READ_X = serde_json::from_str(json).unwrap();
    assert_eq!(event2.res, Some(SyscallResult(5)));
    assert_eq!(event2.data, Some(vec![255, 254, 253, 252, 251]));
}

#[test]
fn test_serde_getcwd_x() {
    let event = PPME_SYSCALL_GETCWD_X {
        res: Some(SyscallResult(0)),
        path: Some(c"/somewhere/far/away"),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(json, r#"{"res":0,"path":"/somewhere/far/away"}"#);

    let event2: owned::PPME_SYSCALL_GETCWD_X = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&event2).unwrap();

    assert_eq!(json, json2);
}
