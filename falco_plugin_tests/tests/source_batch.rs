#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::plugin_collection::source::countdown::{
        check_metrics, CountdownPlugin, COUNTDOWN_PLUGIN_API,
    };
    use falco_plugin_tests::{
        init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, ScapStatus, TestDriver,
    };

    fn test_dummy_next<D: TestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(
            &COUNTDOWN_PLUGIN_API,
            cr#"{"remaining": 4, "batch_size": 4}"#,
        )
        .unwrap();
        let mut driver = driver
            .start_capture(CountdownPlugin::NAME, c"", PlatformData::Disabled)
            .unwrap();

        assert_eq!(
            driver.next_event_as_str().unwrap().unwrap(),
            "3 events remaining"
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

    instantiate_tests!(test_dummy_next);
}
