use falco_plugin::base::Plugin;
use falco_plugin::extract::INVALID_RANGE;
use falco_plugin_tests::plugin_collection::extract::remaining_from_payload::EXTRACT_REMAINING_FROM_PAYLOAD;
use falco_plugin_tests::plugin_collection::source::countdown::{
    CountdownPlugin, COUNTDOWN_PLUGIN_API,
};
use falco_plugin_tests::{
    init_plugin, instantiate_tests, AsPtr, CapturingTestDriver, PlatformData, TestDriver,
};

fn test_without_range<D: TestDriver>() {
    let (mut driver, _) = init_plugin::<D>(
        &COUNTDOWN_PLUGIN_API,
        cr#"{"remaining": 4, "batch_size": 4}"#,
    )
    .unwrap();
    let extract_plugin = driver
        .register_plugin(&EXTRACT_REMAINING_FROM_PAYLOAD, c"")
        .unwrap();
    driver
        .add_filterchecks(&extract_plugin, c"countdown")
        .unwrap();
    let mut driver = driver
        .start_capture(CountdownPlugin::NAME, c"", PlatformData::Disabled)
        .unwrap();

    let event = driver.next_event().unwrap();
    assert_eq!(
        driver
            .event_field_as_string_with_range(c"dummy.payload", &event)
            .unwrap()
            .unwrap(),
        ("3 events remaining".to_string(), INVALID_RANGE),
    );
}

fn test_with_range<D: TestDriver>() {
    let (mut driver, _) = init_plugin::<D>(
        &COUNTDOWN_PLUGIN_API,
        cr#"{"remaining": 4, "batch_size": 4}"#,
    )
    .unwrap();
    let extract_plugin = driver
        .register_plugin(&EXTRACT_REMAINING_FROM_PAYLOAD, c"")
        .unwrap();
    driver
        .add_filterchecks(&extract_plugin, c"countdown")
        .unwrap();
    let mut driver = driver
        .start_capture(CountdownPlugin::NAME, c"", PlatformData::Disabled)
        .unwrap();

    let event = driver.next_event().unwrap();

    let (val, range) = driver
        .event_field_as_string_with_range(c"dummy.payload_with_range", &event)
        .unwrap()
        .unwrap();

    assert_eq!(val, "3 events remaining");

    let raw = event.as_ptr();
    let raw_range =
        unsafe { std::slice::from_raw_parts(raw.add(range.start), range.end - range.start) };
    assert_eq!(raw_range, &b"3 events remaining"[..]);
}

instantiate_tests!(test_without_range; test_with_range);
