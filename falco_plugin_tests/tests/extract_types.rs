use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::fields::types::PT_ABSTIME;
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
use std::time::{Duration, UNIX_EPOCH};

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
                let event = format!("{num_events} events remaining");
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
        PT_ABSTIME,
        PT_ABSTIME::from(UNIX_EPOCH + Duration::from_millis(10)),
        vec![
            PT_ABSTIME::from(UNIX_EPOCH + Duration::from_millis(10)),
            PT_ABSTIME::from(UNIX_EPOCH + Duration::from_millis(20)),
            PT_ABSTIME::from(UNIX_EPOCH + Duration::from_millis(30)),
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
        let expected = $expected;
        let expected = expected.as_slice();
        let actual = $driver
            .extract_field(c_str_macro::c_str!($field_name), &$event)
            .unwrap()
            .unwrap();
        assert!(
            expected.contains(&actual),
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

macro_rules! extract_test_case {
    ($ident:ident, $expected_val_expr:expr, $expected_vec_expr:expr) => {
        mod $ident {
            use super::*;
            use falco_plugin_tests::PlatformData;

            fn test_extract<D: TestDriver>() {
                let (mut driver, plugin) = init_plugin::<D>(&crate::DUMMY_PLUGIN_API, c"").unwrap();
                driver.add_filterchecks(&plugin, c"dummy").unwrap();
                let mut driver = driver
                    .start_capture(crate::DummyPlugin::NAME, c"", PlatformData::Disabled)
                    .unwrap();

                let event = driver.next_event().unwrap();

                assert_field_eq!(
                    driver,
                    event,
                    $ident,
                    $expected_val_expr,
                    $expected_vec_expr
                );
            }

            instantiate_tests!(test_extract);
        }
    };
}

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    #[allow(unused_imports)]
    use falco_plugin::event::fields::types::{PT_ABSTIME, PT_IPNET};
    use falco_plugin_runner::ExtractedField;
    #[allow(unused_imports)] // make rustrover happy, these are very much used
    use falco_plugin_tests::{init_plugin, instantiate_tests};
    use falco_plugin_tests::{CapturingTestDriver, TestDriver};
    use std::ffi::CString;
    #[allow(unused_imports)]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, UNIX_EPOCH};

    extract_test_case!(
        u64,
        [ExtractedField::U64(5)],
        [ExtractedField::Vec(vec![
            ExtractedField::U64(5),
            ExtractedField::U64(6),
            ExtractedField::U64(7)
        ])]
    );

    extract_test_case!(
        string,
        [ExtractedField::String(
            CString::new("Hello, World!").unwrap()
        )],
        [ExtractedField::Vec(vec![
            ExtractedField::String(CString::new("Hello, World!").unwrap()),
            ExtractedField::String(CString::new("Hello, World!").unwrap()),
            ExtractedField::String(CString::new("Hello, World!").unwrap())
        ])]
    );

    extract_test_case!(
        reltime,
        [
            ExtractedField::RelTime(Duration::from_millis(10)),
            ExtractedField::RelTime(Duration::from_millis(20)),
            ExtractedField::RelTime(Duration::from_millis(30))
        ],
        [ExtractedField::Vec(vec![
            ExtractedField::RelTime(Duration::from_millis(10)),
            ExtractedField::RelTime(Duration::from_millis(20)),
            ExtractedField::RelTime(Duration::from_millis(30))
        ])]
    );

    extract_test_case!(
        bool,
        [ExtractedField::Bool(true)],
        [ExtractedField::Vec(vec![
            ExtractedField::Bool(true),
            ExtractedField::Bool(false),
            ExtractedField::Bool(true)
        ])]
    );

    extract_test_case!(
        ipaddr_v4,
        [ExtractedField::IpAddr(IpAddr::V4(Ipv4Addr::LOCALHOST))],
        [ExtractedField::Vec(vec![
            ExtractedField::IpAddr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ExtractedField::IpAddr(IpAddr::V4(Ipv4Addr::BROADCAST)),
            ExtractedField::IpAddr(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        ])]
    );

    extract_test_case!(
        ipaddr_v6,
        [ExtractedField::IpAddr(IpAddr::V6(Ipv6Addr::LOCALHOST))],
        [ExtractedField::Vec(vec![
            ExtractedField::IpAddr(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ExtractedField::IpAddr(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        ])]
    );

    extract_test_case!(
        ipaddr,
        [ExtractedField::IpAddr(IpAddr::V4(Ipv4Addr::LOCALHOST))],
        [ExtractedField::Vec(vec![
            ExtractedField::IpAddr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ExtractedField::IpAddr(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        ])]
    );

    extract_test_case!(
        ipnet_v4,
        [ExtractedField::IpNet(PT_IPNET(IpAddr::V4(
            Ipv4Addr::LOCALHOST
        )))],
        [ExtractedField::Vec(vec![
            ExtractedField::IpNet(PT_IPNET(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            ExtractedField::IpNet(PT_IPNET(IpAddr::V4(Ipv4Addr::BROADCAST))),
            ExtractedField::IpNet(PT_IPNET(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
        ])]
    );

    extract_test_case!(
        ipnet_v6,
        [ExtractedField::IpNet(PT_IPNET(IpAddr::V6(
            Ipv6Addr::LOCALHOST
        )))],
        [ExtractedField::Vec(vec![
            ExtractedField::IpNet(PT_IPNET(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            ExtractedField::IpNet(PT_IPNET(IpAddr::V6(Ipv6Addr::UNSPECIFIED)))
        ])]
    );

    extract_test_case!(
        ipnet,
        [ExtractedField::IpNet(PT_IPNET(IpAddr::V4(
            Ipv4Addr::LOCALHOST
        )))],
        [ExtractedField::Vec(vec![
            ExtractedField::IpNet(PT_IPNET(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            ExtractedField::IpNet(PT_IPNET(IpAddr::V6(Ipv6Addr::UNSPECIFIED)))
        ])]
    );

    extract_test_case!(
        abstime,
        [ExtractedField::AbsTime(
            UNIX_EPOCH + Duration::from_millis(10)
        ),],
        [ExtractedField::Vec(vec![
            ExtractedField::AbsTime(UNIX_EPOCH + Duration::from_millis(10)),
            ExtractedField::AbsTime(UNIX_EPOCH + Duration::from_millis(20)),
            ExtractedField::AbsTime(UNIX_EPOCH + Duration::from_millis(30))
        ])]
    );
}
