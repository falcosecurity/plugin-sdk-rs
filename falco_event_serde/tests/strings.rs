use falco_event::events::types::{PPME_SYSCALL_READ_X, PPME_TRACER_E};
use falco_event::fields::types::{PT_ERRNO, PT_FD};

#[test]
fn test_deserialize_strings() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "TRACER_E": {
        "id": 123,
        "tags": ["tag1", "tag2"],
        "args": [
            ["arg1", "value1"],
            ["arg2", "value2"]
        ]
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_TRACER_E>().unwrap();

    assert_eq!(event.params.id, Some(123));
    assert_eq!(event.params.tags, Some(vec![c"tag1", c"tag2"]));
    assert_eq!(
        event.params.args,
        Some(vec![(c"arg1", c"value1"), (c"arg2", c"value2")])
    );
}

#[test]
fn test_roundtrip_strings() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "TRACER_E": {
        "id": 123,
        "tags": ["tag1", "tag2"],
        "args": [
            ["arg1", "value1"],
            ["arg2", "value2"]
        ]
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_TRACER_E>().unwrap();

    assert_eq!(event.params.id, Some(123));
    assert_eq!(event.params.tags, Some(vec![c"tag1", c"tag2"]));
    assert_eq!(
        event.params.args,
        Some(vec![(c"arg1", c"value1"), (c"arg2", c"value2")])
    );

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}

#[test]
fn test_deserialize_bytebuf() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SYSCALL_READ_X": {
        "res": 10,
        "data": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        "fd": 5,
        "size": 10
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SYSCALL_READ_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(10)));
    assert_eq!(
        event.params.data,
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())
    );
    assert_eq!(event.params.fd, Some(PT_FD(5)));
    assert_eq!(event.params.size, Some(10));
}

#[test]
fn test_roundtrip_bytebuf() {
    // make the byte array invalid UTF-8 so it does roundtrip as a byte array,
    // not a string with tons of \u{...} escapes
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SYSCALL_READ_X": {
        "res": 10,
        "data": [0, 1, 2, 3, 4, 5, 6, 7, 8, 253],
        "fd": 5,
        "size": 10
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SYSCALL_READ_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(10)));
    assert_eq!(
        event.params.data,
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 253].as_slice())
    );
    assert_eq!(event.params.fd, Some(PT_FD(5)));
    assert_eq!(event.params.size, Some(10));

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}
