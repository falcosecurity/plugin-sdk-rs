use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::fields::types::PT_IPNET;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::source::{
    EventBatch, EventInput, PluginEvent, SourcePlugin, SourcePluginInstance,
};
use falco_plugin::strings::CStringWriter;
use falco_plugin::tables::TablesInput;
use falco_plugin::{anyhow, static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct DummyPlugin {
    num_batches: usize,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self { num_batches: 0 })
    }
}

struct DummyPluginInstance(Option<usize>);

impl SourcePluginInstance for DummyPluginInstance {
    type Plugin = DummyPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        plugin.num_batches += 1;
        if let Some(mut num_events) = self.0.take() {
            while num_events > 0 {
                num_events -= 1;
                let event = format!("{} events remaining", num_events);
                let event = Self::plugin_event(event.as_bytes());
                batch.add(event)?;
            }
            Ok(())
        } else {
            Err(anyhow::anyhow!("all events produced").context(FailureReason::Eof))
        }
    }
}

impl SourcePlugin for DummyPlugin {
    type Instance = DummyPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"dummy";
    const PLUGIN_ID: u32 = 1111;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(DummyPluginInstance(Some(4)))
    }

    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
        let event = event.event()?;
        let plugin_event = event.load::<PluginEvent>()?;
        let mut writer = CStringWriter::default();
        write!(
            writer,
            "{}",
            plugin_event
                .params
                .event_data
                .map(|e| String::from_utf8_lossy(e))
                .unwrap_or_default()
        )?;
        Ok(writer.into_cstring())
    }
}

macro_rules! gen_dummy_extractor_fn_impls {
    ($field_name:ident, $ty:ty, $val_expr:expr, $vec_expr:expr) => {
        paste::paste! {
            fn [<extract_ $field_name>](
                &mut self,
                _req: ExtractRequest<Self>
            ) -> Result<$ty, Error> {
                Ok($val_expr)
            }

            fn [<extract_ $field_name _opt>](
                &mut self,
                _req: ExtractRequest<Self>
            ) -> Result<Option<$ty>, Error> {
                Ok(Some($val_expr))
            }

            fn [<extract_ $field_name _opt_none>](
                &mut self,
                _req: ExtractRequest<Self>
            ) -> Result<Option<$ty>, Error> {
                Ok(None)
            }

            fn [<extract_vec_ $field_name>](
                &mut self,
                _req: ExtractRequest<Self>
            ) -> Result<Vec<$ty>, Error> {
                Ok($vec_expr)
            }

            fn [<extract_vec_ $field_name _opt>](
                &mut self,
                _req: ExtractRequest<Self>,
            ) -> Result<Option<Vec<$ty>>, Error> {
                Ok(Some($vec_expr))
            }

            fn [<extract_vec_ $field_name _opt_none>](
                &mut self,
                _req: ExtractRequest<Self>,
            ) -> Result<Option<Vec<$ty>>, Error> {
                Ok(None)
            }
        }
    };
}

impl DummyPlugin {
    gen_dummy_extractor_fn_impls!(u64, u64, 5u64, vec![5u64, 6u64, 7u64]);
    gen_dummy_extractor_fn_impls!(
        string,
        CString,
        CString::new("Hello, World!")?,
        vec![
            CString::new("Hello, World!")?,
            CString::new("Hello, World!")?,
            CString::new("Hello, World!")?
        ]
    );
    gen_dummy_extractor_fn_impls!(
        reltime,
        Duration,
        Duration::from_millis(10),
        vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30)
        ]
    );
    gen_dummy_extractor_fn_impls!(
        abstime,
        SystemTime,
        UNIX_EPOCH + Duration::from_millis(10),
        vec![
            UNIX_EPOCH + Duration::from_millis(10),
            UNIX_EPOCH + Duration::from_millis(20),
            UNIX_EPOCH + Duration::from_millis(30),
        ]
    );
    gen_dummy_extractor_fn_impls!(bool, bool, true, vec![true, false, true]);
    gen_dummy_extractor_fn_impls!(
        ipaddr_v4,
        IpAddr,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        ]
    );
    gen_dummy_extractor_fn_impls!(
        ipaddr_v6,
        IpAddr,
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        ]
    );
    gen_dummy_extractor_fn_impls!(
        ipaddr,
        IpAddr,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        ]
    );
    gen_dummy_extractor_fn_impls!(
        ipnet_v4,
        PT_IPNET,
        PT_IPNET(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        vec![
            PT_IPNET(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            PT_IPNET(IpAddr::V4(Ipv4Addr::BROADCAST)),
            PT_IPNET(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        ]
    );
    gen_dummy_extractor_fn_impls!(
        ipnet_v6,
        PT_IPNET,
        PT_IPNET(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        vec![
            PT_IPNET(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            PT_IPNET(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        ]
    );
    gen_dummy_extractor_fn_impls!(
        ipnet,
        PT_IPNET,
        PT_IPNET(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        vec![
            PT_IPNET(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            PT_IPNET(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        ]
    );
}

macro_rules! gen_fields_variants {
    ($($field_name:ident),*) => {
        &[
            $(
            field(concat!("dummy.", stringify!($field_name)), paste::paste!(&Self::[<extract_ $field_name>])),
            field(concat!("dummy.", stringify!($field_name), "_opt"), paste::paste!(&Self::[<extract_ $field_name _opt>])),
            field(concat!("dummy.", stringify!($field_name), "_opt_none"), paste::paste!(&Self::[<extract_ $field_name _opt_none>])),
            field(concat!("dummy.vec_", stringify!($field_name)), paste::paste!(&Self::[<extract_vec_ $field_name>])),
            field(concat!("dummy.vec_", stringify!($field_name), "_opt"), paste::paste!(&Self::[<extract_vec_ $field_name _opt>])),
            field(concat!("dummy.vec_", stringify!($field_name), "_opt_none"), paste::paste!(&Self::[<extract_vec_ $field_name _opt_none>]))
            ),*
        ]
    };
}

impl ExtractPlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = gen_fields_variants!(
        u64, string, reltime, abstime, bool, ipaddr_v4, ipaddr_v6, ipaddr, ipnet_v4, ipnet_v6,
        ipnet
    );
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);

macro_rules! assert_field_variant_eq {
    ($driver:expr, $event:expr, $field_name:expr, $expected:expr) => {
        let expected = $expected.as_slice();
        let actual = $driver
            .event_field_as_string(c_str_macro::c_str!($field_name), &$event)
            .unwrap()
            .unwrap();
        assert!(
            expected.contains(&actual.as_str()),
            "expected one of {:?} from {}, got {:?}",
            $expected,
            $field_name,
            actual
        );
    };
}

macro_rules! assert_field_eq {
    ($driver:expr, $event:expr, $field_name:ident, $expected_val_expr:expr,
        $expected_vec_expr:expr) => {
        assert_field_variant_eq!(
            $driver,
            $event,
            concat!("dummy.", stringify!($field_name)),
            $expected_val_expr
        );
        assert_field_variant_eq!(
            $driver,
            $event,
            concat!("dummy.", stringify!($field_name), "_opt"),
            $expected_val_expr
        );
        assert!($driver.event_field_is_none(
            c_str_macro::c_str!(concat!("dummy.", stringify!($field_name), "_opt_none")),
            &$event
        ));
        assert_field_variant_eq!(
            $driver,
            $event,
            concat!("dummy.vec_", stringify!($field_name)),
            $expected_vec_expr
        );
        assert_field_variant_eq!(
            $driver,
            $event,
            concat!("dummy.vec_", stringify!($field_name), "_opt"),
            $expected_vec_expr
        );
        assert!($driver.event_field_is_none(
            c_str_macro::c_str!(concat!("dummy.vec_", stringify!($field_name), "_opt_none")),
            &$event
        ));
    };
}

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{init_plugin, instantiate_tests, CapturingTestDriver, TestDriver};
    use std::time::{Duration, UNIX_EPOCH};

    fn epoch_offset_to_rfc3389(offset: Duration) -> String {
        let st = UNIX_EPOCH + offset;
        let dt = chrono::DateTime::<chrono::Local>::from(st);

        dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)
    }

    fn test_dummy_next<D: TestDriver>() {
        let (mut driver, plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"").unwrap();
        driver.add_filterchecks(&plugin, c"dummy").unwrap();
        let mut driver = driver.start_capture(super::DummyPlugin::NAME, c"").unwrap();

        let event = driver.next_event().unwrap();

        assert_field_eq!(driver, event, u64, ["5"], ["(5,6,7)"]);

        assert_field_eq!(
            driver,
            event,
            string,
            ["Hello, World!"],
            ["(Hello, World!,Hello, World!,Hello, World!)"]
        );

        let s = driver
            .event_field_as_string(c"dummy.reltime", &event)
            .unwrap()
            .unwrap();
        assert!(s == "10000000" || s == "10ms");
        let s = driver
            .event_field_as_string(c"dummy.reltime_opt", &event)
            .unwrap()
            .unwrap();
        assert!(s == "10000000" || s == "10ms");
        assert!(driver.event_field_is_none(c"dummy.reltime_opt_none", &event));
        let s = driver
            .event_field_as_string(c"dummy.vec_reltime", &event)
            .unwrap()
            .unwrap();
        assert!(s == "(10000000,20000000,30000000)" || s == "(10ms,20ms,30ms)");
        let s = driver
            .event_field_as_string(c"dummy.vec_reltime_opt", &event)
            .unwrap()
            .unwrap();
        assert!(s == "(10000000,20000000,30000000)" || s == "(10ms,20ms,30ms)");
        assert!(driver.event_field_is_none(c"dummy.vec_reltime_opt_none", &event));

        let ts_10ms = epoch_offset_to_rfc3389(Duration::from_millis(10));
        let ts_20ms = epoch_offset_to_rfc3389(Duration::from_millis(20));
        let ts_30ms = epoch_offset_to_rfc3389(Duration::from_millis(30));
        let s = driver
            .event_field_as_string(c"dummy.abstime", &event)
            .unwrap()
            .unwrap();
        assert!(s == "10000000" || s == ts_10ms);
        let s = driver
            .event_field_as_string(c"dummy.abstime_opt", &event)
            .unwrap()
            .unwrap();
        assert!(s == "10000000" || s == ts_10ms);
        assert!(driver.event_field_is_none(c"dummy.abstime_opt_none", &event));
        let timestamps = format!("({ts_10ms},{ts_20ms},{ts_30ms})");
        let s = driver
            .event_field_as_string(c"dummy.vec_abstime", &event)
            .unwrap()
            .unwrap();
        assert!(s == "(10000000,20000000,30000000)" || s == timestamps);
        let s = driver
            .event_field_as_string(c"dummy.vec_abstime_opt", &event)
            .unwrap()
            .unwrap();
        assert!(s == "(10000000,20000000,30000000)" || s == timestamps);
        assert!(driver.event_field_is_none(c"dummy.vec_abstime_opt_none", &event));

        assert_field_eq!(driver, event, bool, ["true"], ["(true,false,true)"]);

        assert_field_eq!(
            driver,
            event,
            ipaddr_v4,
            ["127.0.0.1"],
            ["(127.0.0.1,255.255.255.255,0.0.0.0)"]
        );

        assert_field_eq!(driver, event, ipaddr_v6, ["::1"], ["(::1,::)"]);

        assert_field_eq!(driver, event, ipaddr, ["127.0.0.1"], ["(127.0.0.1,::)"]);

        assert_field_eq!(
            driver,
            event,
            ipnet_v4,
            ["<IPNET>"],
            ["(<IPNET>,<IPNET>,<IPNET>)"]
        );

        assert_field_eq!(driver, event, ipnet_v6, ["<IPNET>"], ["(<IPNET>,<IPNET>)"]);

        assert_field_eq!(driver, event, ipnet, ["<IPNET>"], ["(<IPNET>,<IPNET>)"]);
    }

    instantiate_tests!(test_dummy_next);
}
