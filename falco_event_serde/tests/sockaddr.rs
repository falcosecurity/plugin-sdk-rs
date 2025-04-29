use falco_event::events::types::PPME_SOCKET_CONNECT_E;
use falco_event::fields::types::{PT_FD, PT_SOCKADDR};

#[test]
fn test_deserialize_sockaddr_v4() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_E": {
        "fd": 1,
        "addr": ["192.168.1.2", 8080]
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(1)));

    match event.params.addr {
        Some(PT_SOCKADDR::V4((addr, port))) => {
            assert_eq!(addr.to_string(), "192.168.1.2");
            assert_eq!(port, 8080);
        }
        _ => panic!("Expected PT_SOCKADDR::V4, got {:?}", event.params.addr),
    }
}

#[test]
fn test_roundtrip_sockaddr_v4() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_E": {
        "fd": 1,
        "addr": ["192.168.1.2", 8080]
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(1)));

    match event.params.addr {
        Some(PT_SOCKADDR::V4((addr, port))) => {
            assert_eq!(addr.to_string(), "192.168.1.2");
            assert_eq!(port, 8080);
        }
        _ => panic!("Expected PT_SOCKADDR::V4, got {:?}", event.params.addr),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}

#[test]
fn test_deserialize_sockaddr_v6() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_E": {
        "fd": 1,
        "addr": ["bad:beef:cafe::f00d", 8080]
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.addr {
        Some(PT_SOCKADDR::V6((addr, port))) => {
            assert_eq!(addr.to_string(), "bad:beef:cafe::f00d");
            assert_eq!(port, 8080);
        }
        _ => panic!("Expected PT_SOCKADDR::V6, got {:?}", event.params.addr),
    }
}

#[test]
fn test_roundtrip_sockaddr_v6() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_E": {
        "fd": 1,
        "addr": ["bad:beef:cafe::f00d", 8080]
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.addr {
        Some(PT_SOCKADDR::V6((addr, port))) => {
            assert_eq!(addr.to_string(), "bad:beef:cafe::f00d");
            assert_eq!(port, 8080);
        }
        _ => panic!("Expected PT_SOCKADDR::V6, got {:?}", event.params.addr),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}

#[test]
fn test_deserialize_sockaddr_unix() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_E": {
        "fd": 1,
        "addr": "/tmp/socket.sock"
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.addr {
        Some(PT_SOCKADDR::Unix(addr)) => {
            assert_eq!(addr.as_bytes(), b"/tmp/socket.sock");
        }
        _ => panic!("Expected PT_SOCKADDR::Unix, got {:?}", event.params.addr),
    }
}

#[test]
fn test_roundtrip_sockaddr_unix() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_E": {
        "fd": 1,
        "addr": "/tmp/socket.sock"
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.addr {
        Some(PT_SOCKADDR::Unix(addr)) => {
            assert_eq!(addr.as_bytes(), b"/tmp/socket.sock");
        }
        _ => panic!("Expected PT_SOCKADDR::Unix, got {:?}", event.params.addr),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}

#[test]
fn test_deserialize_sockaddr_other() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_E": {
        "fd": 1,
        "addr": [7, "/tmp/socket.sock"]
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.addr {
        Some(PT_SOCKADDR::Other(af, addr)) => {
            assert_eq!(af, 7);
            assert_eq!(addr, b"/tmp/socket.sock");
        }
        _ => panic!("Expected PT_SOCKADDR::Other, got {:?}", event.params.addr),
    }
}

#[test]
fn test_roundtrip_sockaddr_other() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SOCKET_CONNECT_E": {
        "fd": 1,
        "addr": [7, "/tmp/socket.sock"]
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SOCKET_CONNECT_E>().unwrap();

    assert_eq!(event.params.fd, Some(PT_FD(1)));
    match event.params.addr {
        Some(PT_SOCKADDR::Other(af, addr)) => {
            assert_eq!(af, 7);
            assert_eq!(addr, b"/tmp/socket.sock");
        }
        _ => panic!("Expected PT_SOCKADDR::Other, got {:?}", event.params.addr),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}
