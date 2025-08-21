use falco_plugin::base::Plugin;
use falco_plugin_tests::plugin_collection::extract::remaining_from_payload::EXTRACT_REMAINING_FROM_PAYLOAD;
use falco_plugin_tests::plugin_collection::source::countdown::{
    check_metrics, CountdownPlugin, COUNTDOWN_PLUGIN_API,
};
use falco_plugin_tests::{
    init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, ScapStatus, TestDriver,
};

fn test_extract<D: TestDriver>() {
    let (mut driver, _) = init_plugin::<D>(
        &COUNTDOWN_PLUGIN_API,
        cr#"{"remaining": 4, "batch_size": 4}"#,
    )
    .unwrap();
    let plugin = driver
        .register_plugin(&EXTRACT_REMAINING_FROM_PAYLOAD, c"")
        .unwrap();
    driver.add_filterchecks(&plugin, c"countdown").unwrap();
    let mut driver = driver
        .start_capture(CountdownPlugin::NAME, c"", PlatformData::Disabled)
        .unwrap();

    let event = driver.next_event().unwrap();
    assert_eq!(
        driver
            .event_field_as_string(c"evt.plugininfo", &event)
            .unwrap()
            .unwrap(),
        "3 events remaining"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"dummy.payload", &event)
            .unwrap()
            .unwrap(),
        "3 events remaining"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"dummy.payload_repeated[2]", &event)
            .unwrap()
            .unwrap(),
        "(3 events remaining,3 events remaining)"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"dummy.remaining", &event)
            .unwrap()
            .unwrap(),
        "3"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"dummy.remaining_with_maybe_override", &event)
            .unwrap()
            .unwrap(),
        "3"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"dummy.remaining_with_maybe_override[7eleven]", &event)
            .unwrap()
            .unwrap(),
        "7"
    );
    assert!(driver
        .event_field_as_string(c"dummy.remaining_with_maybe_override[eleven]", &event)
        .is_err());
    assert_eq!(
        driver
            .event_field_as_string(c"dummy.remaining_repeated[5]", &event)
            .unwrap()
            .unwrap(),
        "(3,3,3,3,3)"
    );
    check_metrics(&mut driver, 1, 4);

    assert_eq!(
        driver.next_event_as_str().unwrap().unwrap(),
        "2 events remaining"
    );
    check_metrics(&mut driver, 1, 4);

    assert_eq!(
        driver.next_event_as_str().unwrap().unwrap(),
        "1 events remaining"
    );
    check_metrics(&mut driver, 1, 4);

    assert_eq!(
        driver.next_event_as_str().unwrap().unwrap(),
        "0 events remaining"
    );

    let event = driver.next_event();
    check_metrics(&mut driver, 2, 4);
    assert!(matches!(event, Err(ScapStatus::Eof)))
}

instantiate_tests!(test_extract);
