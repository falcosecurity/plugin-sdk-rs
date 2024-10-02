use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::fields::types::PT_IPNET;
use falco_plugin::extract::{
    field, ExtractFieldInfo, ExtractFieldRequestArg, ExtractPlugin, ExtractRequest,
};
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

impl DummyPlugin {
    fn extract_u64(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<u64, Error> {
        Ok(5u64)
    }

    fn extract_vec_u64(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<u64>, Error> {
        Ok(vec![5u64, 6u64, 7u64])
    }

    fn extract_string(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<CString, Error> {
        Ok(CString::new("Hello, World!")?)
    }

    fn extract_vec_string(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<CString>, Error> {
        let s = CString::new("Hello, World!")?;
        Ok(vec![s.clone(), s.clone(), s.clone()])
    }

    fn extract_reltime(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Duration, Error> {
        Ok(Duration::from_millis(10))
    }

    fn extract_vec_reltime(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<Duration>, Error> {
        Ok(vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
        ])
    }

    fn extract_abstime(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<SystemTime, Error> {
        Ok(UNIX_EPOCH + Duration::from_millis(10))
    }

    fn extract_vec_abstime(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<SystemTime>, Error> {
        Ok(vec![
            UNIX_EPOCH + Duration::from_millis(10),
            UNIX_EPOCH + Duration::from_millis(20),
            UNIX_EPOCH + Duration::from_millis(30),
        ])
    }

    fn extract_bool(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<bool, Error> {
        Ok(true)
    }

    fn extract_vec_bool(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<bool>, Error> {
        Ok(vec![true, false, true])
    }

    fn extract_ipaddr_v4(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<IpAddr, Error> {
        Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    fn extract_ipaddr_v6(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<IpAddr, Error> {
        Ok(IpAddr::V6(Ipv6Addr::LOCALHOST))
    }

    fn extract_vec_ipaddr(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<IpAddr>, Error> {
        Ok(vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ])
    }

    fn extract_ipnet_v4(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<PT_IPNET, Error> {
        Ok(PT_IPNET(IpAddr::V4(Ipv4Addr::LOCALHOST)))
    }

    fn extract_ipnet_v6(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<PT_IPNET, Error> {
        Ok(PT_IPNET(IpAddr::V6(Ipv6Addr::LOCALHOST)))
    }

    fn extract_vec_ipnet(
        &mut self,
        _req: ExtractRequest<Self>,
        _arg: ExtractFieldRequestArg,
    ) -> Result<Vec<PT_IPNET>, Error> {
        Ok(vec![
            PT_IPNET(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            PT_IPNET(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ])
    }
}

impl ExtractPlugin for DummyPlugin {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy.u64", &Self::extract_u64),
        field("dummy.vec_u64", &Self::extract_vec_u64),
        field("dummy.string", &Self::extract_string),
        field("dummy.vec_string", &Self::extract_vec_string),
        field("dummy.reltime", &Self::extract_reltime),
        field("dummy.vec_reltime", &Self::extract_vec_reltime),
        field("dummy.abstime", &Self::extract_abstime),
        field("dummy.vec_abstime", &Self::extract_vec_abstime),
        field("dummy.bool", &Self::extract_bool),
        field("dummy.vec_bool", &Self::extract_vec_bool),
        field("dummy.ipaddr_v4", &Self::extract_ipaddr_v4),
        field("dummy.ipaddr_v6", &Self::extract_ipaddr_v6),
        field("dummy.vec_ipaddr", &Self::extract_vec_ipaddr),
        field("dummy.ipnet_v4", &Self::extract_ipnet_v4),
        field("dummy.ipnet_v6", &Self::extract_ipnet_v6),
        field("dummy.vec_ipnet", &Self::extract_vec_ipnet),
    ];
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{init_plugin, instantiate_tests, CapturingTestDriver, TestDriver};

    fn test_dummy_next<D: TestDriver>() {
        let (mut driver, plugin) = init_plugin::<D>(&super::DUMMY_PLUGIN_API, c"").unwrap();
        driver.add_filterchecks(&plugin, c"dummy").unwrap();
        let mut driver = driver.start_capture(super::DummyPlugin::NAME, c"").unwrap();

        let event = driver.next_event().unwrap();
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.u64", &event)
                .unwrap()
                .unwrap(),
            "5"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.vec_u64", &event)
                .unwrap()
                .unwrap(),
            "(5,6,7)"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.string", &event)
                .unwrap()
                .unwrap(),
            "Hello, World!"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.vec_string", &event)
                .unwrap()
                .unwrap(),
            "(Hello, World!,Hello, World!,Hello, World!)"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.reltime", &event)
                .unwrap()
                .unwrap(),
            "10000000"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.vec_reltime", &event)
                .unwrap()
                .unwrap(),
            "(10000000,20000000,30000000)"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.abstime", &event)
                .unwrap()
                .unwrap(),
            "10000000"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.vec_abstime", &event)
                .unwrap()
                .unwrap(),
            "(10000000,20000000,30000000)"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.bool", &event)
                .unwrap()
                .unwrap(),
            "true"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.vec_bool", &event)
                .unwrap()
                .unwrap(),
            "(true,false,true)"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.ipaddr_v4", &event)
                .unwrap()
                .unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.ipaddr_v6", &event)
                .unwrap()
                .unwrap(),
            "::1"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.vec_ipaddr", &event)
                .unwrap()
                .unwrap(),
            "(127.0.0.1,::1)"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.ipnet_v4", &event)
                .unwrap()
                .unwrap(),
            "<IPNET>"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.ipnet_v6", &event)
                .unwrap()
                .unwrap(),
            "<IPNET>"
        );
        assert_eq!(
            driver
                .event_field_as_string(c"dummy.vec_ipnet", &event)
                .unwrap()
                .unwrap(),
            "(<IPNET>,<IPNET>)"
        );
    }

    instantiate_tests!(test_dummy_next);
}
