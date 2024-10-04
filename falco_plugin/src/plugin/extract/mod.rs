use crate::extract::{EventInput, ExtractArgType};
use crate::plugin::base::Plugin;
use crate::plugin::extract::schema::ExtractFieldInfo;
use crate::tables::TableReader;
use falco_event::events::types::EventType;
use falco_plugin_api::ss_plugin_extract_field;
use std::any::TypeId;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::sync::Mutex;
use thiserror::Error;

pub mod fields;
pub mod schema;
#[doc(hidden)]
pub mod wrappers;

/// The actual argument passed to the extractor function
///
/// It is validated based on the [`ExtractFieldInfo`] definition (use [`ExtractFieldInfo::with_arg`]
/// to specify the expected argument type).
///
/// **Note**: this type describes the actual argument in a particular invocation.
/// For describing the type of arguments the extractor accepts, please see [`ExtractArgType`]`
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExtractFieldRequestArg<'a> {
    /// no argument, the extractor was invoked as plain `field_name`
    None,
    /// an integer argument, the extractor was invoked as e.g. `field_name[1]`
    Int(u64),
    /// a string argument, the extractor was invoked as e.g. `field_name[foo]`
    String(&'a CStr),
}

#[derive(Debug, Error)]
pub enum ArgError {
    #[error("required argument missing")]
    Missing,

    #[error("unexpected argument")]
    Unexpected,

    #[error("expected string argument")]
    ExpectedString,

    #[error("expected int argument")]
    ExpectedInt,
}

pub trait ExtractField {
    unsafe fn key_unchecked(&self) -> ExtractFieldRequestArg;

    unsafe fn key(&self, arg_type: ExtractArgType) -> Result<ExtractFieldRequestArg, ArgError> {
        let key = unsafe { self.key_unchecked() };
        match key {
            k @ ExtractFieldRequestArg::None => match arg_type {
                ExtractArgType::None => Ok(k),
                ExtractArgType::OptionalIndex => Ok(k),
                ExtractArgType::OptionalKey => Ok(k),
                ExtractArgType::RequiredIndex => Err(ArgError::Missing),
                ExtractArgType::RequiredKey => Err(ArgError::Missing),
            },
            k @ ExtractFieldRequestArg::Int(_) => match arg_type {
                ExtractArgType::None => Err(ArgError::Unexpected),
                ExtractArgType::OptionalIndex => Ok(k),
                ExtractArgType::OptionalKey => Err(ArgError::ExpectedString),
                ExtractArgType::RequiredIndex => Ok(k),
                ExtractArgType::RequiredKey => Err(ArgError::ExpectedString),
            },
            k @ ExtractFieldRequestArg::String(_) => match arg_type {
                ExtractArgType::None => Err(ArgError::Unexpected),
                ExtractArgType::OptionalIndex => Err(ArgError::ExpectedInt),
                ExtractArgType::OptionalKey => Ok(k),
                ExtractArgType::RequiredIndex => Err(ArgError::ExpectedInt),
                ExtractArgType::RequiredKey => Ok(k),
            },
        }
    }
}

impl ExtractField for ss_plugin_extract_field {
    unsafe fn key_unchecked(&self) -> ExtractFieldRequestArg {
        if self.arg_present == 0 {
            return ExtractFieldRequestArg::None;
        }

        if self.arg_key.is_null() {
            return ExtractFieldRequestArg::Int(self.arg_index);
        }

        unsafe { ExtractFieldRequestArg::String(CStr::from_ptr(self.arg_key)) }
    }
}

/// An extraction request
#[derive(Debug)]
pub struct ExtractRequest<'c, 'e, 't, P: ExtractPlugin> {
    /// a context instance, potentially shared between extractions
    pub context: &'c mut P::ExtractContext,

    /// the event being processed
    pub event: &'e EventInput,

    /// an interface to access tables exposed from Falco core and other plugins
    ///
    /// See [`crate::tables`] for details
    pub table_reader: &'t TableReader,
}

/// # Support for field extraction plugins
pub trait ExtractPlugin: Plugin + Sized
where
    Self: 'static,
{
    /// The set of event types supported by this plugin
    ///
    /// If empty, the plugin will get invoked for all event types, otherwise it will only
    /// get invoked for event types from this list.
    ///
    /// **Note**: some notable event types are:
    /// - [`EventType::ASYNCEVENT_E`], generated from async plugins
    /// - [`EventType::PLUGINEVENT_E`], generated from source plugins
    const EVENT_TYPES: &'static [EventType];
    /// The set of event sources supported by this plugin
    ///
    /// If empty, the plugin will get invoked for events coming from all sources, otherwise it will
    /// only get invoked for events from sources named in this list.
    ///
    /// **Note**: one notable event source is called `syscall`
    const EVENT_SOURCES: &'static [&'static str];

    /// The extraction context
    ///
    /// It might be useful if your plugin supports multiple fields, and they all share some common
    /// preprocessing steps. Instead of redoing the preprocessing for each field, intermediate
    /// results can be stored in the context for subsequent extractions (from the same event).
    ///
    /// If you do not need a context to share between extracting fields of the same event, use `()`
    /// as the type.
    ///
    /// Since the context is created using the [`Default`] trait, you may prefer to use an Option
    /// wrapping the actual context type:
    ///
    /// ```ignore
    /// impl ExtractPlugin for MyPlugin {
    ///     type ExtractContext = Option<ActualContext>;
    ///     // ...
    /// }
    ///
    /// impl MyPlugin {
    ///     fn make_context(&mut self, ...) -> ActualContext { /* ... */ }
    ///
    ///     fn extract_field_one(
    ///         &mut self,
    ///         req: ExtractContext<Self>,
    ///         arg: ExtractRequestArg) -> ... {
    ///         let context = req.context.get_or_insert_with(|| self.make_context(...));
    ///
    ///         // use context
    ///     }
    /// }
    /// ```
    type ExtractContext: Default + 'static;

    /// The actual list of extractable fields
    ///
    /// An extraction method is a method with the following signature:
    /// ```ignore
    /// use anyhow::Error;
    /// use falco_plugin::extract::{EventInput, ExtractFieldRequestArg, ExtractRequest};
    /// use falco_plugin::tables::TableReader;
    ///
    /// fn extract_sample(
    ///     &mut self,
    ///     req: ExtractRequest<Self>,
    ///     arg: ExtractFieldRequestArg,
    /// ) -> Result<R, Error>;
    ///
    /// ```
    /// where `R` is one of the following types or a [`Vec`] of them:
    /// - [`u64`]
    /// - [`bool`]
    /// - [`CString`]
    /// - [`std::time::SystemTime`]
    /// - [`std::time::Duration`]
    /// - [`std::net::IpAddr`]
    /// - [`falco_event::fields::types::PT_IPNET`]
    ///
    /// `req` is the extraction request ([`ExtractRequest`]), containing the context in which
    /// the plugin is doing the work.
    ///
    /// `arg` is the actual argument passed along with the field (see [`ExtractFieldRequestArg`])
    ///
    /// To register extracted fields, add them to the [`ExtractPlugin::EXTRACT_FIELDS`] array, wrapped via [`crate::extract::field`]:
    /// ```
    /// use std::ffi::CStr;
    /// use falco_plugin::event::events::types::EventType;
    /// use falco_plugin::event::events::types::EventType::PLUGINEVENT_E;
    /// use falco_plugin::anyhow::Error;
    /// use falco_plugin::base::Plugin;
    /// use falco_plugin::extract::{
    ///     field,
    ///     ExtractArgType,
    ///     ExtractFieldInfo,
    ///     ExtractFieldRequestArg,
    ///     ExtractPlugin,
    ///     ExtractRequest};
    /// use falco_plugin::tables::TablesInput;
    ///
    /// struct SampleExtractPlugin;
    ///
    /// impl Plugin for SampleExtractPlugin {
    ///      const NAME: &'static CStr = c"dummy";
    ///      const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    ///      const DESCRIPTION: &'static CStr = c"test plugin";
    ///      const CONTACT: &'static CStr = c"rust@localdomain.pl";
    ///      type ConfigType = ();
    ///
    ///      fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
    ///          Ok(Self)
    ///      }
    /// }
    ///
    /// impl SampleExtractPlugin {
    ///     fn extract_sample(
    ///         &mut self,
    ///         _req: ExtractRequest<Self>,
    ///         _arg: ExtractFieldRequestArg,
    ///     ) -> Result<u64, Error> {
    ///         Ok(10u64)
    ///     }
    ///
    ///     fn extract_arg(
    ///         &mut self,
    ///         _req: ExtractRequest<Self>,
    ///         arg: ExtractFieldRequestArg,
    ///     ) -> Result<u64, Error> {
    ///         match arg {
    ///             ExtractFieldRequestArg::Int(i) => Ok(i),
    ///             _ => anyhow::bail!("wanted an int argument, got {:?}", arg)
    ///         }
    ///     }
    /// }
    ///
    /// impl ExtractPlugin for SampleExtractPlugin {
    ///     const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    ///     const EVENT_SOURCES: &'static [&'static str] = &["dummy"];
    ///     type ExtractContext = ();
    ///     const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
    ///         field("sample.always_10", &Self::extract_sample),
    ///         field("sample.arg", &Self::extract_arg).with_arg(ExtractArgType::RequiredIndex),
    ///     ];
    /// }
    ///
    /// ```
    ///
    /// **Note**: while the returned field type is automatically determined based on the return type
    /// of the function, the argument type defaults to [`ExtractArgType::None`] and must be explicitly specified
    /// using [`ExtractFieldInfo::with_arg`] if the function expects an argument.
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>];

    /// Generate the field schema for the Falco plugin framework
    ///
    /// The default implementation inspects all fields from [`Self::EXTRACT_FIELDS`] and generates
    /// a JSON description in the format expected by the framework.
    ///
    /// You probably won't need to provide your own implementation.
    fn get_fields() -> &'static CStr {
        static FIELD_SCHEMA: Mutex<BTreeMap<TypeId, CString>> = Mutex::new(BTreeMap::new());

        let ty = TypeId::of::<Self>();
        let mut schema_map = FIELD_SCHEMA.lock().unwrap();
        // Safety:
        //
        // we only generate the string once and never change or delete it
        // so the pointer should remain valid for the static lifetime
        // hence the dance of converting a reference to a raw pointer and back
        // to erase the lifetime
        unsafe {
            CStr::from_ptr(
                schema_map
                    .entry(ty)
                    .or_insert_with(|| {
                        let schema = serde_json::to_string_pretty(&Self::EXTRACT_FIELDS)
                            .expect("failed to serialize extraction schema");
                        CString::new(schema.into_bytes())
                            .expect("failed to add NUL to extraction schema")
                    })
                    .as_ptr(),
            )
        }
    }

    /// Perform the actual field extraction
    ///
    /// The default implementation creates an empty context and loops over all extraction
    /// requests, invoking the relevant function to actually generate the field value.
    ///
    /// You probably won't need to provide your own implementation.
    fn extract_fields<'a>(
        &'a mut self,
        event_input: &EventInput,
        table_reader: &TableReader,
        fields: &mut [ss_plugin_extract_field],
        storage: &'a mut bumpalo::Bump,
    ) -> Result<(), anyhow::Error> {
        let mut context = Self::ExtractContext::default();

        for req in fields {
            let info = Self::EXTRACT_FIELDS
                .get(req.field_id as usize)
                .ok_or_else(|| anyhow::anyhow!("field index out of bounds"))?;

            let request = ExtractRequest::<Self> {
                context: &mut context,
                event: event_input,
                table_reader,
            };

            info.func.extract(self, req, request, info.arg, storage)?;
        }
        Ok(())
    }
}
