use crate::event::Event;
use crate::plugin::event_source_filter::EventSourceFilter;
use crate::plugin::get_last_owner_error;
use crate::tables::{TABLE_READER, TABLE_READER_EXT};
use falco_event::fields::types::PT_IPNET;
use falco_event::fields::FromBytes;
use falco_plugin_api::{
    plugin_api__bindgen_ty_2, ss_plugin_extract_field, ss_plugin_extract_field__bindgen_ty_1,
    ss_plugin_field_extract_input, ss_plugin_owner_t, ss_plugin_rc, ss_plugin_rc_SS_PLUGIN_FAILURE,
    ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_t,
};
use serde::Deserialize;
use std::ffi::{CStr, CString};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

#[derive(Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExtractFieldType {
    String = 9,
    Uint64 = 8,
    Bool = 25,
    RelTime = 20,
    AbsTime = 21,
    IpAddr = 40,
    IpNet = 41,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExtractFieldArg {
    #[serde(default)]
    is_required: bool,
    #[serde(default)]
    is_index: bool,
    #[serde(default)]
    is_key: bool,
}

#[derive(Deserialize, Debug)]
pub struct ExtractFieldDescriptor {
    name: String,

    #[serde(rename = "type")]
    field_type: ExtractFieldType,

    #[serde(rename = "isList")]
    is_list: bool,

    arg: Option<ExtractFieldArg>,

    #[allow(dead_code)]
    display: Option<String>,
    #[allow(dead_code)]
    desc: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExtractedField {
    None,
    U64(u64),
    Bool(bool),
    RelTime(std::time::Duration),
    AbsTime(std::time::SystemTime),
    String(CString),
    IpAddr(IpAddr),
    IpNet(PT_IPNET),
    Vec(Vec<ExtractedField>),
}

impl Display for ExtractedField {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractedField::None => write!(f, "None"),
            ExtractedField::U64(value) => write!(f, "{}", value),
            ExtractedField::String(cstr) => write!(f, "{:?}", cstr),
            ExtractedField::Vec(vector) => {
                let mut first = true;
                write!(f, "(")?;
                for val in vector {
                    if first {
                        first = false;
                    } else {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", val)?;
                }
                write!(f, ")")?;
                Ok(())
            }
            ExtractedField::Bool(b) => {
                if *b {
                    write!(f, "true")
                } else {
                    write!(f, "false")
                }
            }
            ExtractedField::RelTime(t) => {
                write!(f, "{:?}", t)
            }
            ExtractedField::AbsTime(t) => {
                write!(f, "{:?}", t)
            }
            ExtractedField::IpAddr(addr) => {
                write!(f, "{:?}", addr)
            }
            ExtractedField::IpNet(_) => {
                write!(f, "<IPNET>")
            }
        }
    }
}

fn extract_one(
    data: *const ss_plugin_extract_field__bindgen_ty_1,
    ftype: u32,
) -> anyhow::Result<ExtractedField> {
    let ftype = match ftype {
        9 => ExtractFieldType::String,
        8 => ExtractFieldType::Uint64,
        25 => ExtractFieldType::Bool,
        20 => ExtractFieldType::RelTime,
        21 => ExtractFieldType::AbsTime,
        40 => ExtractFieldType::IpAddr,
        41 => ExtractFieldType::IpNet,
        _ => anyhow::bail!("Unsupported field type: {}", ftype),
    };

    match ftype {
        ExtractFieldType::String => {
            let ptr = unsafe { *(*data).str_ };
            if ptr.is_null() {
                Ok(ExtractedField::None)
            } else {
                let cs = unsafe { CStr::from_ptr(ptr) };
                let cs = CString::from(cs);
                Ok(ExtractedField::String(cs))
            }
        }
        ExtractFieldType::Uint64 => {
            let val = unsafe { *(*data).u64_ };
            Ok(ExtractedField::U64(val))
        }
        ExtractFieldType::Bool => {
            let val = unsafe { *(*data).boolean };
            Ok(ExtractedField::Bool(val != 0))
        }
        ExtractFieldType::RelTime => {
            let val = unsafe { *(*data).u64_ };
            let rt = std::time::Duration::from_nanos(val);
            Ok(ExtractedField::RelTime(rt))
        }
        ExtractFieldType::AbsTime => {
            let val = unsafe { *(*data).u64_ };
            let st = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(val);
            Ok(ExtractedField::AbsTime(st))
        }
        ExtractFieldType::IpAddr => {
            let bytebuf = unsafe { (*data).buf };
            let mut bytebuf = unsafe {
                std::slice::from_raw_parts((*bytebuf).ptr.cast::<u8>(), (*bytebuf).len as usize)
            };
            let ip = IpAddr::from_bytes(&mut bytebuf)?;
            Ok(ExtractedField::IpAddr(ip))
        }
        ExtractFieldType::IpNet => {
            let bytebuf = unsafe { (*data).buf };
            let mut bytebuf = unsafe {
                std::slice::from_raw_parts((*bytebuf).ptr.cast::<u8>(), (*bytebuf).len as usize)
            };
            let ip = IpAddr::from_bytes(&mut bytebuf)?;
            Ok(ExtractedField::IpNet(PT_IPNET(ip)))
        }
    }
}

fn extract_many(
    data: *const ss_plugin_extract_field__bindgen_ty_1,
    ftype: u32,
    len: usize,
) -> anyhow::Result<ExtractedField> {
    let ftype = match ftype {
        9 => ExtractFieldType::String,
        8 => ExtractFieldType::Uint64,
        25 => ExtractFieldType::Bool,
        20 => ExtractFieldType::RelTime,
        21 => ExtractFieldType::AbsTime,
        40 => ExtractFieldType::IpAddr,
        41 => ExtractFieldType::IpNet,
        _ => anyhow::bail!("Unsupported field type: {}", ftype),
    };

    match ftype {
        ExtractFieldType::String => {
            let raw = unsafe { std::slice::from_raw_parts((*data).str_, len) };
            Ok(ExtractedField::Vec(
                raw.iter()
                    .map(|val| {
                        if val.is_null() {
                            ExtractedField::None
                        } else {
                            let cs = unsafe { CStr::from_ptr(*val) };
                            let cs = CString::from(cs);
                            ExtractedField::String(cs)
                        }
                    })
                    .collect(),
            ))
        }
        ExtractFieldType::Uint64 => {
            let raw = unsafe { std::slice::from_raw_parts((*data).u64_, len) };
            Ok(ExtractedField::Vec(
                raw.iter().map(|val| ExtractedField::U64(*val)).collect(),
            ))
        }
        ExtractFieldType::Bool => {
            let raw = unsafe { std::slice::from_raw_parts((*data).boolean, len) };
            Ok(ExtractedField::Vec(
                raw.iter()
                    .map(|val| ExtractedField::Bool(*val != 0))
                    .collect(),
            ))
        }
        ExtractFieldType::RelTime => {
            let raw = unsafe { std::slice::from_raw_parts((*data).u64_, len) };
            Ok(ExtractedField::Vec(
                raw.iter()
                    .map(|val| ExtractedField::RelTime(std::time::Duration::from_nanos(*val)))
                    .collect(),
            ))
        }
        ExtractFieldType::AbsTime => {
            let raw = unsafe { std::slice::from_raw_parts((*data).u64_, len) };
            Ok(ExtractedField::Vec(
                raw.iter()
                    .map(|val| {
                        ExtractedField::AbsTime(
                            std::time::SystemTime::UNIX_EPOCH
                                + std::time::Duration::from_nanos(*val),
                        )
                    })
                    .collect(),
            ))
        }
        ExtractFieldType::IpAddr => {
            let raw = unsafe { std::slice::from_raw_parts((*data).buf, len) };
            Ok(ExtractedField::Vec(
                raw.iter()
                    .filter_map(|bytebuf| {
                        let mut bytebuf = unsafe {
                            std::slice::from_raw_parts(
                                bytebuf.ptr.cast::<u8>(),
                                bytebuf.len as usize,
                            )
                        };
                        IpAddr::from_bytes(&mut bytebuf)
                            .map(ExtractedField::IpAddr)
                            .ok()
                    })
                    .collect(),
            ))
        }
        ExtractFieldType::IpNet => {
            let raw = unsafe { std::slice::from_raw_parts((*data).buf, len) };
            Ok(ExtractedField::Vec(
                raw.iter()
                    .filter_map(|bytebuf| {
                        let mut bytebuf = unsafe {
                            std::slice::from_raw_parts(
                                bytebuf.ptr.cast::<u8>(),
                                bytebuf.len as usize,
                            )
                        };
                        IpAddr::from_bytes(&mut bytebuf)
                            .map(PT_IPNET)
                            .map(ExtractedField::IpNet)
                            .ok()
                    })
                    .collect(),
            ))
        }
    }
}

pub struct ExtractPlugin {
    owner: *mut ss_plugin_owner_t,
    plugin: *mut ss_plugin_t,
    api: *const plugin_api__bindgen_ty_2,
    fields: Vec<ExtractFieldDescriptor>,
    filter: EventSourceFilter,
}

impl ExtractPlugin {
    pub fn new(
        owner: *mut ss_plugin_owner_t,
        plugin: *mut ss_plugin_t,
        api: *const plugin_api__bindgen_ty_2,
        filter: EventSourceFilter,
    ) -> anyhow::Result<Self> {
        let get_fields = unsafe { &*api }
            .get_fields
            .ok_or_else(|| anyhow::anyhow!("`get_fields` not found"))?;
        let fields = unsafe { get_fields() };
        anyhow::ensure!(!fields.is_null(), "null pointer from `get_fields`");
        let s = unsafe { CStr::from_ptr(fields) };
        let fields = serde_json::from_slice(s.to_bytes())?;

        Ok(Self {
            owner,
            plugin,
            api,
            fields,
            filter,
        })
    }

    fn api(&self) -> &plugin_api__bindgen_ty_2 {
        unsafe { &*self.api }
    }

    pub fn extract(
        &self,
        event: &Event,
        field: &str,
    ) -> Option<Result<ExtractedField, ss_plugin_rc>> {
        if !self.filter.matches(event) {
            return None;
        }

        let mut split = field.split('[');
        let field = split.next().unwrap();
        let mut maybe_arg = split.next();
        if let Some(ref mut arg) = maybe_arg {
            if arg.find(']') == Some(arg.len() - 1) {
                *arg = &arg[..arg.len() - 1];
            } else {
                return Some(Err(ss_plugin_rc_SS_PLUGIN_FAILURE));
            }
        }
        let arg_is_present = maybe_arg.is_some();
        let mut index_arg = 0;

        let (idx, desc) = self
            .fields
            .iter()
            .enumerate()
            .find(|(_, f)| f.name == field)?;

        if let Some(ref arg_type) = desc.arg {
            if let Some(arg) = maybe_arg {
                if arg_type.is_index {
                    index_arg = match arg.parse() {
                        Ok(val) => val,
                        Err(_) => return Some(Err(ss_plugin_rc_SS_PLUGIN_FAILURE)),
                    };
                    maybe_arg = None;
                } else if !arg_type.is_key {
                    return Some(Err(ss_plugin_rc_SS_PLUGIN_FAILURE));
                }
            } else if arg_type.is_required {
                return Some(Err(ss_plugin_rc_SS_PLUGIN_FAILURE));
            }
        }

        let maybe_arg = match maybe_arg.map(CString::new) {
            Some(Ok(arg)) => Some(arg),
            Some(Err(_)) => return Some(Err(ss_plugin_rc_SS_PLUGIN_FAILURE)),
            None => None,
        };

        let event_input = event.to_event_input();
        let field_cstr = match CString::new(field) {
            Ok(cstr) => cstr,
            Err(_) => return Some(Err(ss_plugin_rc_SS_PLUGIN_FAILURE)),
        };

        let mut extract_fields = ss_plugin_extract_field {
            res: ss_plugin_extract_field__bindgen_ty_1 {
                u64_: std::ptr::null_mut(),
            },
            res_len: 0,
            field_id: idx as u32,
            field: field_cstr.as_ptr(),
            arg_key: maybe_arg
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            arg_index: index_arg,
            arg_present: arg_is_present as u32,
            ftype: desc.field_type as u32,
            flist: desc.is_list as u32,
        };

        let extract_input = ss_plugin_field_extract_input {
            owner: self.owner,
            get_owner_last_error: Some(get_last_owner_error),
            num_fields: 1,
            fields: &mut extract_fields,
            table_reader: TABLE_READER,
            table_reader_ext: &TABLE_READER_EXT as *const _ as *mut _,
        };

        let extract = self.api().extract_fields?;

        let rc = unsafe { extract(self.plugin, &event_input, &extract_input) };
        if rc != ss_plugin_rc_SS_PLUGIN_SUCCESS {
            return Some(Err(rc));
        }

        if extract_fields.res_len == 0 {
            Some(Ok(ExtractedField::None))
        } else if extract_fields.res_len == 1 {
            match extract_one(&extract_fields.res, extract_fields.ftype) {
                Ok(res) => Some(Ok(res)),
                Err(_) => Some(Err(ss_plugin_rc_SS_PLUGIN_FAILURE)),
            }
        } else {
            match extract_many(
                &extract_fields.res,
                extract_fields.ftype,
                extract_fields.res_len as usize,
            ) {
                Ok(res) => Some(Ok(res)),
                Err(_) => Some(Err(ss_plugin_rc_SS_PLUGIN_FAILURE)),
            }
        }
    }
}
