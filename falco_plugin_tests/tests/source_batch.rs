use falco_plugin::base::Plugin;
use falco_plugin_tests::plugin_collection::source::countdown::{
    check_metrics, CountdownPlugin, COUNTDOWN_PLUGIN_API,
};
use falco_plugin_tests::{
    init_plugin, instantiate_tests, CapturingTestDriver, PlatformData, ScapStatus, TestDriver,
};
use std::ffi::CStr;

fn test_source_batch_sized<D: TestDriver>(size: usize) {
    let config = format!(r#"{{"remaining": {size}, "batch_size": {size}}}"#);
    let mut config = config.into_bytes();
    config.push(0);
    let config = CStr::from_bytes_with_nul(&config).unwrap();
    let (driver, _plugin) = init_plugin::<D>(&COUNTDOWN_PLUGIN_API, config).unwrap();
    let mut driver = driver
        .start_capture(CountdownPlugin::NAME, c"", PlatformData::Disabled)
        .unwrap();

    for n in 0..size {
        assert_eq!(
            driver.next_event_as_str().unwrap().unwrap(),
            format!("{} events remaining", size - n - 1)
        );
    }

    let event = driver.next_event();
    check_metrics(&mut driver, 2, size);
    assert!(matches!(event, Err(ScapStatus::Eof)))
}

fn test_source_batch_1<D: TestDriver>() {
    test_source_batch_sized::<D>(100)
}

fn test_source_batch_10<D: TestDriver>() {
    test_source_batch_sized::<D>(100)
}

fn test_source_batch_100<D: TestDriver>() {
    test_source_batch_sized::<D>(100)
}

fn test_source_batch_1000<D: TestDriver>() {
    test_source_batch_sized::<D>(100)
}

instantiate_tests!(test_source_batch_1;test_source_batch_10;test_source_batch_100;test_source_batch_1000);
