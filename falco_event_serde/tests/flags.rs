use falco_event::events::types::{PPME_SOCKET_SHUTDOWN_E, PPME_SYSCALL_OPEN_E};
use falco_event::fields::types::{
    PT_ENUMFLAGS8_shutdown_how, PT_FD, PT_FLAGS32_file_flags, PT_FSPATH,
};

#[test]
fn test_deserialize_flags() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SYSCALL_OPEN_E": {
        "name": "/tmp/testfile",
        "flags": 2,
        "mode": 420
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SYSCALL_OPEN_E>().unwrap();

    assert_eq!(event.params.name, Some(PT_FSPATH::new(b"/tmp/testfile")));
    assert_eq!(event.params.flags, Some(PT_FLAGS32_file_flags::O_WRONLY));
    assert_eq!(event.params.mode, Some(0o644));
}

#[test]
fn test_roundtrip_flags() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SYSCALL_OPEN_E": {
        "name": "/tmp/testfile",
        "flags": 2,
        "mode": 420
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SYSCALL_OPEN_E>().unwrap();

    assert_eq!(event.params.name, Some(PT_FSPATH::new(b"/tmp/testfile")));
    assert_eq!(event.params.flags, Some(PT_FLAGS32_file_flags::O_WRONLY));
    assert_eq!(event.params.mode, Some(0o644));

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}

#[test]
fn test_deserialize_enumflags() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_SHUTDOWN_E": {
        "fd": 13,
        "how": 1
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_SHUTDOWN_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(13)));
    assert_eq!(event.params.how, Some(PT_ENUMFLAGS8_shutdown_how::SHUT_WR));
}

#[test]
fn test_roundtrip_enumflags() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_SHUTDOWN_E": {
        "fd": 13,
        "how": 1
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_SHUTDOWN_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(13)));
    assert_eq!(event.params.how, Some(PT_ENUMFLAGS8_shutdown_how::SHUT_WR));

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}
