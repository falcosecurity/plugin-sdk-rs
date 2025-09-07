use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::ffi::{CStr, CString};

/// # Specification of open parameters for a source plugin instance
///
/// **Note**: this appears unused as of API version 3.4.0
#[derive(Debug)]
pub enum OpenParam<'a> {
    /// # A single string valid as a sample open parameter
    Item {
        /// the value itself
        value: &'a str,
        /// the description
        desc: &'a str,
    },
    /// # A sequence of strings, each valid as a sample open parameter
    Seq {
        /// the values itself
        values: &'a [&'a str],
        /// the description
        desc: &'a str,
        /// the separator used to join the values together
        separator: char,
    },
}

impl Serialize for OpenParam<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OpenParam::Item { value, desc } => {
                let mut ss = serializer.serialize_struct("param", 2)?;
                ss.serialize_field("value", value)?;
                ss.serialize_field("desc", desc)?;
                ss.end()
            }
            OpenParam::Seq {
                values,
                desc,
                separator,
            } => {
                let mut sep = [0u8; 4];
                let sep = separator.encode_utf8(sep.as_mut_slice());
                let value = values.join(sep);
                let mut ss = serializer.serialize_struct("param", 3)?;
                ss.serialize_field("value", value.as_str())?;
                ss.serialize_field("desc", desc)?;
                ss.serialize_field("separator", &separator)?;
                ss.end()
            }
        }
    }
}

/// # Serialize the open parameter specification
///
/// This function can be used in [`SourcePlugin::list_open_params`](`crate::source::SourcePlugin::list_open_params`)
/// to describe the allowed values for the instance open parameters.
///
/// **Note**: this appears unused as of API version 3.4.0
pub fn serialize_open_params<'a>(
    params: &[OpenParam],
    storage: &'a mut CString,
) -> Result<&'a CStr, anyhow::Error> {
    let buf = serde_json::to_string_pretty(params)?;
    let mut buf = CString::new(buf)?;
    std::mem::swap(&mut buf, storage);
    Ok(storage.as_c_str())
}
