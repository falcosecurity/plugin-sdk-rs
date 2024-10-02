use cxx::{type_id, ExternType};
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum ScapStatus {
    Ok,
    Failure,
    Timeout,
    Eof,
    NotSupported,
    Other(i32),
}

impl Display for ScapStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScapStatus::Ok => f.write_str("OK"),
            ScapStatus::Failure => f.write_str("Failure"),
            ScapStatus::Timeout => f.write_str("Timeout"),
            ScapStatus::Eof => f.write_str("Eof"),
            ScapStatus::NotSupported => f.write_str("NotSupported"),
            ScapStatus::Other(rc) => write!(f, "Other({})", rc),
        }
    }
}

pub struct CaptureNotStarted;

pub struct CaptureStarted;

#[repr(transparent)]
pub struct Api(pub falco_plugin::api::plugin_api);

unsafe impl ExternType for Api {
    type Id = type_id!("falco_plugin_api");
    type Kind = cxx::kind::Opaque;
}

pub struct SinspMetric {
    pub name: String,
    pub value: u64,
}
