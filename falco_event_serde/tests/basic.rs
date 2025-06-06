use falco_event::events::types::PPME_GENERIC_E;
use falco_event::fields::types::PT_SYSCALLID;

#[test]
fn test_basic_deserialize() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "GENERIC_E": {
        "id": 1,
        "native_id": 1001
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_GENERIC_E>().unwrap();
    assert_eq!(event.params.id, Some(PT_SYSCALLID(1)));
    assert_eq!(event.params.native_id, Some(1001));
}

#[test]
fn test_basic_roundtrip() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "GENERIC_E": {
        "id": 1,
        "native_id": 1001
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_GENERIC_E>().unwrap();
    assert_eq!(event.params.id, Some(PT_SYSCALLID(1)));
    assert_eq!(event.params.native_id, Some(1001));

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}
