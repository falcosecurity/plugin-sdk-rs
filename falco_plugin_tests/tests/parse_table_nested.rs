use falco_plugin::base::Plugin;
use falco_plugin_tests::plugin_collection::extract::extra_fields::EXTRACT_EXTRA_FIELDS_API;
use falco_plugin_tests::plugin_collection::extract::nested::EXTRACT_NESTED_API;
use falco_plugin_tests::plugin_collection::extract::remaining_from_table::EXTRACT_REMAINING_FROM_TABLE_API;
use falco_plugin_tests::plugin_collection::parse::nested_table_extra_fields::PARSE_NESTED_TABLE_EXTRA_FIELDS_API;
use falco_plugin_tests::plugin_collection::parse::remaining_into_nested_table::PARSE_INTO_NESTED_TABLE_API;
use falco_plugin_tests::plugin_collection::source::countdown::{
    CountdownPlugin, COUNTDOWN_PLUGIN_API,
};
use falco_plugin_tests::{
    init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, ScapStatus, TestDriver,
};

fn test_parse_table_nested<D: TestDriver>() {
    let (mut driver, _plugin) = init_plugin::<D>(
        &COUNTDOWN_PLUGIN_API,
        cr#"{"remaining": 4, "batch_size": 4}"#,
    )
    .unwrap();
    driver
        .register_plugin(&PARSE_INTO_NESTED_TABLE_API, c"")
        .unwrap();
    let extract_remaining_plugin = driver
        .register_plugin(&EXTRACT_REMAINING_FROM_TABLE_API, c"")
        .unwrap();
    let extract_extra_fields_plugin = driver
        .register_plugin(&EXTRACT_EXTRA_FIELDS_API, c"")
        .unwrap();
    let extract_plugin = driver.register_plugin(&EXTRACT_NESTED_API, c"").unwrap();
    driver
        .register_plugin(&PARSE_NESTED_TABLE_EXTRA_FIELDS_API, c"")
        .unwrap();
    driver
        .add_filterchecks(&extract_remaining_plugin, c"countdown")
        .unwrap();
    driver
        .add_filterchecks(&extract_extra_fields_plugin, c"countdown")
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
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.is_even", &event)
            .unwrap()
            .unwrap(),
        "0"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.is_final[3]", &event)
            .unwrap()
            .unwrap(),
        "1"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.is_final[0]", &event)
            .unwrap()
            .unwrap(),
        "0"
    );
    assert!(driver
        .event_field_as_string(c"countdown.is_final[4]", &event)
        .is_err());
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.as_string", &event)
            .unwrap()
            .unwrap(),
        "3 events remaining"
    );

    let event = driver.next_event().unwrap();
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.remaining", &event)
            .unwrap()
            .unwrap(),
        "2"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.is_even", &event)
            .unwrap()
            .unwrap(),
        "1"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.is_final[2]", &event)
            .unwrap()
            .unwrap(),
        "1"
    );
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.is_final[0]", &event)
            .unwrap()
            .unwrap(),
        "0"
    );
    assert!(driver
        .event_field_as_string(c"countdown.is_final[3]", &event)
        .is_err());
    assert_eq!(
        driver
            .event_field_as_string(c"countdown.as_string", &event)
            .unwrap()
            .unwrap(),
        "2 events remaining"
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

instantiate_tests!(test_parse_table_nested);
