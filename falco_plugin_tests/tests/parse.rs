use falco_plugin::base::Plugin;
use falco_plugin_tests::plugin_collection::extract::remaining_from_table::EXTRACT_REMAINING_FROM_TABLE_API;
use falco_plugin_tests::plugin_collection::parse::remaining_into_table_direct::PARSE_REMAINING_INTO_TABLE_DIRECT_PLUGIN_API;
use falco_plugin_tests::plugin_collection::source::countdown::{
    CountdownPlugin, COUNTDOWN_PLUGIN_API,
};
use falco_plugin_tests::{
    init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, ScapStatus, TestDriver,
};

fn test_parse<D: TestDriver>() {
    let (mut driver, _plugin) = init_plugin::<D>(
        &COUNTDOWN_PLUGIN_API,
        cr#"{"remaining": 4, "batch_size": 4}"#,
    )
    .unwrap();
    let _ = driver.register_plugin(&PARSE_REMAINING_INTO_TABLE_DIRECT_PLUGIN_API, c"");
    let extract_plugin = driver
        .register_plugin(&EXTRACT_REMAINING_FROM_TABLE_API, c"")
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
            .event_field_as_string(c"countdown.remaining", &event)
            .unwrap()
            .unwrap(),
        "3"
    );
    let event = driver.next_event().unwrap();
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.remaining", &event)
            .unwrap()
            .unwrap(),
        "2"
    );
    let event = driver.next_event().unwrap();
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.remaining", &event)
            .unwrap()
            .unwrap(),
        "1"
    );
    let event = driver.next_event().unwrap();
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.remaining", &event)
            .unwrap()
            .unwrap(),
        "0"
    );

    let event = driver.next_event();
    assert!(matches!(event, Err(ScapStatus::Eof)))
}

instantiate_tests!(test_parse);
