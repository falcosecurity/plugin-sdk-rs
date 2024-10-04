use crate::extract::ExtractFieldRequestArg;
use crate::plugin::extract::fields::{Extract, ExtractFieldTypeId};
use crate::plugin::extract::{ExtractField, ExtractPlugin, ExtractRequest};
use anyhow::Error;
use falco_plugin_api::ss_plugin_extract_field;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::fmt::{Debug, Formatter};

/// The type of argument a field extractor expects
///
/// If a request comes with an argument not conforming to the spec
/// (e.g. an argument where none was requested), the SDK will return an error
/// and not invoke the extractor function at all.
#[derive(Clone, Copy, Debug)]
pub enum ExtractArgType {
    /// no argument, extraction requested as `field_name`
    None,
    /// optional integer argument, extraction requested as `field_name` or `field_name[1]`
    OptionalIndex,
    /// optional string argument, extraction requested as `field_name` or `field_name[foo]`
    OptionalKey,
    /// required integer argument, extraction requested as `field_name[1]`
    RequiredIndex,
    /// required string argument, extraction requested as `field_name[foo]`
    RequiredKey,
}

impl Serialize for ExtractArgType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ExtractArgType::None => serializer.serialize_none(),
            ExtractArgType::OptionalIndex => {
                let mut ss = serializer.serialize_struct("arg", 1)?;
                ss.serialize_field("isIndex", &true)?;
                ss.end()
            }
            ExtractArgType::OptionalKey => {
                let mut ss = serializer.serialize_struct("arg", 1)?;
                ss.serialize_field("isKey", &true)?;
                ss.end()
            }
            ExtractArgType::RequiredIndex => {
                let mut ss = serializer.serialize_struct("arg", 2)?;
                ss.serialize_field("isIndex", &true)?;
                ss.serialize_field("isRequired", &true)?;
                ss.end()
            }
            ExtractArgType::RequiredKey => {
                let mut ss = serializer.serialize_struct("arg", 2)?;
                ss.serialize_field("isKey", &true)?;
                ss.serialize_field("isRequired", &true)?;
                ss.end()
            }
        }
    }
}

pub fn serialize_field_type<S: Serializer>(
    f: &ExtractFieldTypeId,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match f {
        ExtractFieldTypeId::U64 => serializer.serialize_str("uint64"),
        ExtractFieldTypeId::String => serializer.serialize_str("string"),
        ExtractFieldTypeId::RelTime => serializer.serialize_str("reltime"),
        ExtractFieldTypeId::AbsTime => serializer.serialize_str("abstime"),
        ExtractFieldTypeId::Bool => serializer.serialize_str("bool"),
        ExtractFieldTypeId::IpAddr => serializer.serialize_str("ipaddr"),
        ExtractFieldTypeId::IpNet => serializer.serialize_str("ipnet"),
    }
}

pub trait Extractor<P: ExtractPlugin> {
    fn extract<'a>(
        &self,
        plugin: &'a mut P,
        field: &mut ss_plugin_extract_field,
        request: ExtractRequest<'a, '_, '_, P>,
        arg_type: ExtractArgType,
        storage: &'a mut bumpalo::Bump,
    ) -> Result<(), Error>;
}

impl<P, R, F> Extractor<P> for F
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(&mut P, ExtractRequest<P>, ExtractFieldRequestArg) -> Result<R, Error>,
{
    fn extract<'a>(
        &self,
        plugin: &'a mut P,
        field: &mut ss_plugin_extract_field,
        request: ExtractRequest<'a, '_, '_, P>,
        arg_type: ExtractArgType,
        storage: &'a mut bumpalo::Bump,
    ) -> Result<(), Error> {
        let result = self(plugin, request, unsafe { field.key(arg_type) }?)?;
        Ok(result.extract_to(field, storage)?)
    }
}

/// # A description of an extracted field
///
/// You should create instances of this struct by calling [`field`].
///
/// This struct is used to automatically generate the schema definition for the Falco plugin framework
#[derive(Serialize)]
pub struct ExtractFieldInfo<P: ExtractPlugin> {
    /// the name of the extracted field, generally of the form `<plugin>.<field>`
    pub name: &'static str,
    #[serde(rename = "type")]
    #[serde(serialize_with = "serialize_field_type")]
    /// the type of the extracted field
    pub field_type: ExtractFieldTypeId,
    #[serde(rename = "isList")]
    /// if true, the extract function returns a [`Vec`] of values, not a single one
    pub is_list: bool,
    /// the type of argument the extract function takes
    pub arg: ExtractArgType,
    #[serde(rename = "display")]
    /// the display name for the extracted field, defaulting to the name
    pub display_name: Option<&'static str>,
    #[serde(rename = "desc")]
    /// a description for the extracted field, mandatory but defaults to the name
    pub description: &'static str,
    #[serde(skip)]
    /// the function implementing the actual extraction
    pub func: &'static dyn Extractor<P>,
}

impl<P: ExtractPlugin> Debug for ExtractFieldInfo<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

impl<P: ExtractPlugin> ExtractFieldInfo<P> {
    /// Specify the type of argument the field extractor takes
    ///
    /// See [`ExtractArgType`] for the possible values
    pub const fn with_arg(mut self, extract_arg_type: ExtractArgType) -> Self {
        self.arg = extract_arg_type;
        self
    }

    /// Set the display name fdr the extracted field
    pub const fn with_display(mut self, display_name: &'static str) -> Self {
        self.display_name = Some(display_name);
        self
    }

    /// Set the description for the extracted field
    pub const fn with_description(mut self, description: &'static str) -> Self {
        self.description = description;
        self
    }
}

/// Wrap a function or method to make it usable as a field extractor
///
/// See [ExtractPlugin::EXTRACT_FIELDS](`crate::extract::ExtractPlugin::EXTRACT_FIELDS`)
pub const fn field<P, R, F>(name: &'static str, func: &'static F) -> ExtractFieldInfo<P>
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(&mut P, ExtractRequest<P>, ExtractFieldRequestArg) -> Result<R, Error>,
{
    ExtractFieldInfo {
        name,
        field_type: <R as Extract>::TYPE_ID,
        is_list: <R as Extract>::IS_LIST,
        arg: ExtractArgType::None,
        display_name: None,
        description: name,
        func: func as &'static dyn Extractor<P>,
    }
}
