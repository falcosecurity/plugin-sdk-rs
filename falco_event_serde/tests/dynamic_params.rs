use falco_event::events::types::PPME_SYSCALL_BPF_X;
use falco_event::fields::types::{PT_DYN_bpf_dynamic_param, PT_FD};

#[test]
fn test_deserialize_dynamic() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SYSCALL_BPF_X": {
        "res_or_fd": {
            "PPM_BPF_IDX_FD": 1
        }
    }
    }"#;

    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SYSCALL_BPF_X>().unwrap();

    match event.params.res_or_fd {
        Some(PT_DYN_bpf_dynamic_param::PPM_BPF_IDX_FD(idx)) => {
            assert_eq!(idx, PT_FD(1));
        }
        _ => panic!("Expected PPM_BPF_IDX_FD, got {:?}", event.params.res_or_fd),
    }
}

#[test]
fn test_roundtrip_dynamic() {
    let json = r#"{
    "ts": 1700000000,
    "tid": 12345,
    "SYSCALL_BPF_X": {
        "res_or_fd": {
            "PPM_BPF_IDX_FD": 1
        }
    }
    }"#;

    let json_value: serde_json::Value = serde_json::from_str(json).unwrap();
    let event: falco_event_serde::de::Event = serde_json::from_str(json).unwrap();
    let bytes = event.to_vec();
    let event = falco_event::events::RawEvent::from(&bytes).unwrap();
    let event = event.load::<PPME_SYSCALL_BPF_X>().unwrap();

    match event.params.res_or_fd {
        Some(PT_DYN_bpf_dynamic_param::PPM_BPF_IDX_FD(idx)) => {
            assert_eq!(idx, PT_FD(1));
        }
        _ => panic!("Expected PPM_BPF_IDX_FD, got {:?}", event.params.res_or_fd),
    }

    let ser = falco_event_serde::ser::Event::from(&event);
    let json_output = serde_json::to_value(ser).unwrap();
    assert_eq!(json_value, json_output);
}
