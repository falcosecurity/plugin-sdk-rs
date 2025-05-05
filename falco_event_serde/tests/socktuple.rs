use falco_event::events::types::PPME_SOCKET_CONNECT_X;
use falco_event::fields::types::{PT_ERRNO, PT_FD, PT_SOCKTUPLE};

#[test]
fn test_deserialize_socktuple_v4() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_X": {
        "res": 0,
        "tuple": ["192.168.1.2", 8080, "192.168.88.1", 9090],
        "fd": 1
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(0)));
    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.tuple {
        Some(PT_SOCKTUPLE::V4 { source, dest }) => {
            assert_eq!(source.ip().to_string(), "192.168.1.2");
            assert_eq!(source.port(), 8080);
            assert_eq!(dest.ip().to_string(), "192.168.88.1");
            assert_eq!(dest.port(), 9090);
        }
        _ => panic!("Expected PT_SOCKTUPLE::V4, got {:?}", event.params.tuple),
    }
}

#[test]
fn test_deserialize_socktuple_v6() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_X": {
        "res": 0,
        "tuple": ["bad:beef:cafe::f00d", 8080, "f00d::c0ff:ee", 9090],
        "fd": 1
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(0)));
    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.tuple {
        Some(PT_SOCKTUPLE::V6 { source, dest }) => {
            assert_eq!(source.ip().to_string(), "bad:beef:cafe::f00d");
            assert_eq!(source.port(), 8080);
            assert_eq!(dest.ip().to_string(), "f00d::c0ff:ee");
            assert_eq!(dest.port(), 9090);
        }
        _ => panic!("Expected PT_SOCKTUPLE::V6, got {:?}", event.params.tuple),
    }
}

#[test]
fn test_deserialize_socktuple_unix() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_X": {
        "res": 0,
        "tuple": [12345, 67890, "/var/run/nscd/socket"],
        "fd": 1
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(0)));
    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.tuple {
        Some(PT_SOCKTUPLE::Unix {
            source_ptr,
            dest_ptr,
            path,
        }) => {
            assert_eq!(source_ptr, 12345);
            assert_eq!(dest_ptr, 67890);
            assert_eq!(path.as_bytes(), b"/var/run/nscd/socket");
        }
        _ => panic!("Expected PT_SOCKTUPLE::Unix, got {:?}", event.params.tuple),
    }
}

#[test]
fn test_deserialize_socktuple_other() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_X": {
        "res": 0,
        "tuple": [7, "/var/run/nscd/socket"],
        "fd": 1
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(0)));
    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.tuple {
        Some(PT_SOCKTUPLE::Other(af, addr)) => {
            assert_eq!(af, 7);
            assert_eq!(addr, b"/var/run/nscd/socket");
        }
        _ => panic!("Expected PT_SOCKTUPLE::Other, got {:?}", event.params.tuple),
    }
}

#[test]
fn test_roundtrip_socktuple_v4() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_X": {
        "res": 0,
        "tuple": ["192.168.1.2", 8080, "192.168.88.1", 9090],
        "fd": 1
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(0)));
    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.tuple {
        Some(PT_SOCKTUPLE::V4 { source, dest }) => {
            assert_eq!(source.ip().to_string(), "192.168.1.2");
            assert_eq!(source.port(), 8080);
            assert_eq!(dest.ip().to_string(), "192.168.88.1");
            assert_eq!(dest.port(), 9090);
        }
        _ => panic!("Expected PT_SOCKTUPLE::V4, got {:?}", event.params.tuple),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}

#[test]
fn test_roundtrip_socktuple_v6() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_X": {
        "res": 0,
        "tuple": ["bad:beef:cafe::f00d", 8080, "f00d::c0ff:ee", 9090],
        "fd": 1
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(0)));
    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.tuple {
        Some(PT_SOCKTUPLE::V6 { source, dest }) => {
            assert_eq!(source.ip().to_string(), "bad:beef:cafe::f00d");
            assert_eq!(source.port(), 8080);
            assert_eq!(dest.ip().to_string(), "f00d::c0ff:ee");
            assert_eq!(dest.port(), 9090);
        }
        _ => panic!("Expected PT_SOCKTUPLE::V6, got {:?}", event.params.tuple),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}

#[test]
fn test_roundtrip_socktuple_unix() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_X": {
        "res": 0,
        "tuple": [12345, 67890, "/var/run/nscd/socket"],
        "fd": 1
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(0)));
    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.tuple {
        Some(PT_SOCKTUPLE::Unix {
            source_ptr,
            dest_ptr,
            path,
        }) => {
            assert_eq!(source_ptr, 12345);
            assert_eq!(dest_ptr, 67890);
            assert_eq!(path.as_bytes(), b"/var/run/nscd/socket");
        }
        _ => panic!("Expected PT_SOCKTUPLE::Unix, got {:?}", event.params.tuple),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}

#[test]
fn test_roundtrip_socktuple_other() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_X": {
        "res": 0,
        "tuple": [7, "/var/run/nscd/socket"],
        "fd": 1
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_X>().unwrap();

    assert_eq!(event.params.res, Some(PT_ERRNO(0)));
    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.tuple {
        Some(PT_SOCKTUPLE::Other(af, addr)) => {
            assert_eq!(af, 7);
            assert_eq!(addr, b"/var/run/nscd/socket");
        }
        _ => panic!("Expected PT_SOCKTUPLE::Other, got {:?}", event.params.tuple),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}
