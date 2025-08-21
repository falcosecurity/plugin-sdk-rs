use anyhow::{Context, Error};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::static_plugin;
use falco_plugin::strings::WriteIntoCString;
use falco_plugin::tables::TablesInput;
use std::ffi::{CStr, CString};
use std::io::Write;

struct ExtractRemainingFromPayload;

impl Plugin for ExtractRemainingFromPayload {
    const NAME: &'static CStr = c"extract_remaining_from_payload";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"test plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

impl ExtractRemainingFromPayload {
    fn extract_payload(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let mut out = CString::default();
        out.write_into(|w| w.write_all(payload))?;
        Ok(out)
    }

    fn extract_payload_repeated(
        &mut self,
        req: ExtractRequest<Self>,
        reps: u64,
    ) -> Result<Vec<CString>, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let mut out = CString::default();
        out.write_into(|w| w.write_all(payload))?;
        Ok(vec![out; reps as usize])
    }

    fn extract_events_remaining(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let first_char = &payload[0..1];
        let first_char = std::str::from_utf8(first_char)?;
        let remaining = first_char.parse()?;
        Ok(remaining)
    }

    fn events_remaining_repeated(
        &mut self,
        req: ExtractRequest<Self>,
        reps: u64,
    ) -> Result<Vec<u64>, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;
        let payload = event
            .params
            .event_data
            .ok_or_else(|| anyhow::anyhow!("no payload in event"))?;

        let first_char = &payload[0..1];
        let first_char = std::str::from_utf8(first_char)?;
        let remaining: u64 = first_char.parse()?;
        Ok(vec![remaining; reps as usize])
    }

    fn extract_events_remaining_with_maybe_override(
        &mut self,
        req: ExtractRequest<Self>,
        arg: Option<&CStr>,
    ) -> Result<u64, Error> {
        let event = req.event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;

        let buf = match arg {
            Some(s) => s.to_bytes(),
            None => event
                .params
                .event_data
                .ok_or_else(|| anyhow::anyhow!("no payload in event"))?,
        };

        let first_char = &buf[0..1];
        let first_char = std::str::from_utf8(first_char).context(format!("buf={buf:?}"))?;
        let remaining = first_char.parse()?;
        Ok(remaining)
    }
}

impl ExtractPlugin for ExtractRemainingFromPayload {
    const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["countdown"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy.payload", &Self::extract_payload),
        field("dummy.payload_repeated", &Self::extract_payload_repeated),
        field("dummy.remaining", &Self::extract_events_remaining),
        field("dummy.remaining_repeated", &Self::events_remaining_repeated),
        field(
            "dummy.remaining_with_maybe_override",
            &Self::extract_events_remaining_with_maybe_override,
        ),
    ];
}

static_plugin!(pub EXTRACT_REMAINING_FROM_PAYLOAD = ExtractRemainingFromPayload);
