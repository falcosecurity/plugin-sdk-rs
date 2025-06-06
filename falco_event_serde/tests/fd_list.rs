use falco_event::events::types::PPME_SYSCALL_POLL_E;
use falco_event::fields::types::PT_FLAGS16_file_flags;

#[test]
fn test_deserialize_fd_list() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SYSCALL_POLL_E": {
        "fds": [
        [1, 2]
        ],
        "timeout": 1000
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SYSCALL_POLL_E>().unwrap();

    assert_eq!(event.params.timeout, Some(1000));
    let fds = event.params.fds.unwrap().0;
    assert_eq!(fds.len(), 1);
    assert_eq!(fds[0].0, 1);
    assert_eq!(fds[0].1, PT_FLAGS16_file_flags::O_WRONLY);
}

#[test]
fn test_roundtrip_fd_list() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SYSCALL_POLL_E": {
        "fds": [
        [1, 2]
        ],
        "timeout": 1000
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SYSCALL_POLL_E>().unwrap();

    assert_eq!(event.params.timeout, Some(1000));
    let fds = event.params.fds.clone().unwrap().0;
    assert_eq!(fds.len(), 1);
    assert_eq!(fds[0].0, 1);
    assert_eq!(fds[0].1, PT_FLAGS16_file_flags::O_WRONLY);

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}
