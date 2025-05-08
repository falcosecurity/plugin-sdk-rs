use crate::extract::EventInput;
use crate::plugin::base::Plugin;
use crate::plugin::extract::schema::ExtractFieldInfo;
use crate::plugin::extract::wrappers::ExtractPluginExported;
use crate::tables::LazyTableReader;
use falco_event::events::types::EventType;
use falco_plugin_api::{ss_plugin_extract_field, ss_plugin_extract_value_offsets};
use std::any::TypeId;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::ops::Range;
use std::sync::Mutex;

mod extractor_fn;
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

pub trait ExtractField {
    unsafe fn key_unchecked(&self) -> ExtractFieldRequestArg;
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

/// An invalid range (not supported)
///
/// This is used when an extractor that does not support ranges is used together with extractors
/// that do, and range extraction is requested. Due to the design of the Falco plugin API,
/// there must be a range for all the fields (or none of them), so we fill out the missing ranges
/// with this value.
///
/// **Note**: you should not use this value in plugins yourself. If an extractor returns data that is
/// not corresponding to any particular byte offset in the plugin payload, it should set the range
/// to [`UNSPECIFIED_RANGE`].
#[allow(clippy::reversed_empty_ranges)]
pub const INVALID_RANGE: Range<usize> = 1..0;

/// An unspecified range (computed data)
///
/// Use this range to indicate that the extracted value does not correspond to any specific
/// byte range in the event (for example, it was calculated based on the event data).
pub const UNSPECIFIED_RANGE: Range<usize> = 0..0;

/// The offset in the event where a plugin event payload starts
///
/// Since the event payload is at a fixed offset, you can add this value
/// to the start of an extracted field within the payload to get the offset
/// from the start of the event.
///
/// 26 bytes for the event header, plus 2*4 bytes for the parameter lengths,
/// plus 4 bytes for the plugin ID.
const PLUGIN_EVENT_PAYLOAD_OFFSET: usize = 38;

/// Range extraction request/response
#[derive(Debug, Eq, PartialEq)]
pub enum ExtractByteRange {
    /// Range extraction was not requested
    NotRequested,

    /// Range extraction was requested but not performed
    ///
    /// This value is set upon entry to the extractor function. The function may replace the value
    /// with [`ExtractByteRange::Found`] if it supports finding byte ranges. If the extractor does
    /// not support byte ranges, it can ignore this value completely and leave it unchanged.
    Requested,

    /// Range extraction finished successfully
    ///
    /// Note that for fields extracted from the plugin event data field, you will probably want
    /// to construct this value using [`ExtractByteRange::in_plugin_data`].
    Found(Range<usize>),
}

impl ExtractByteRange {
    /// Create a range pointing into a plugin event data field
    ///
    /// This is a helper for the common case of returning offsets inside the data field
    /// of a plugin event. It simply shifts the provided range by 38 bytes (26 header bytes,
    /// 2*4 length bytes, 4 plugin id bytes) to make the resulting range relative to the full
    /// event buffer.
    pub fn in_plugin_data(range: Range<usize>) -> Self {
        Self::Found(
            PLUGIN_EVENT_PAYLOAD_OFFSET + range.start..PLUGIN_EVENT_PAYLOAD_OFFSET + range.end,
        )
    }
}

/// An extraction request
#[derive(Debug)]
pub struct ExtractRequest<'c, 'e, 't, P: ExtractPlugin> {
    /// A context instance, potentially shared between extractions
    pub context: &'c mut P::ExtractContext,

    /// The event being processed
    pub event: &'e EventInput,

    /// An interface to access tables exposed from Falco core and other plugins
    ///
    /// See [`crate::tables`] for details.
    pub table_reader: &'t LazyTableReader<'t>,

    /// Offset of extracted data in event payload
    ///
    /// If set to [`ExtractByteRange::Requested`], and the plugin supports it, replace this
    /// with a [`ExtractByteRange::Found`] containing the byte range containing the extracted value,
    /// *within the whole event buffer*. In the typical case of a range inside the plugin event
    /// data, you can use the [`ExtractByteRange::in_plugin_data`] helper.
    ///
    /// If the data is computed (not directly coming from any byte range in the event), use
    /// [`UNSPECIFIED_RANGE`] instead.
    ///
    /// **Note**: range support is optional, and this field can be ignored.
    pub offset: &'c mut ExtractByteRange,
}

/// Support for field extraction plugins
pub trait ExtractPlugin: Plugin + ExtractPluginExported + Sized
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
    ///         req: ExtractContext<Self>) -> ... {
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
    ///     arg: A, // optional
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
    /// and `A` is the argument to the field extraction:
    ///
    /// | Argument declaration | `field` lookup | `field[5]` lookup | `field[foo]` lookup |
    /// |----------------------|----------------|-------------------|---------------------|
    /// | _missing_            | valid          | -                 | -                   |
    /// | `arg: u64`           | -              | valid             | -                   |
    /// | `arg: Option<u64>`   | valid          | valid             | -                   |
    /// | `arg: &CStr`         | -              | -                 | valid               |
    /// | `arg: Option<&CStr>` | valid          | -                 | valid               |
    ///
    /// `req` is the extraction request ([`ExtractRequest`]), containing the context in which
    /// the plugin is doing the work.
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
    ///     ExtractFieldInfo,
    ///     ExtractPlugin,
    ///     ExtractRequest};
    ///# use falco_plugin::{extract_plugin, plugin};
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
    ///     ) -> Result<u64, Error> {
    ///         Ok(10u64)
    ///     }
    ///
    ///     fn extract_arg(
    ///         &mut self,
    ///         _req: ExtractRequest<Self>,
    ///         arg: u64,
    ///     ) -> Result<u64, Error> {
    ///         Ok(arg)
    ///     }
    /// }
    ///
    /// impl ExtractPlugin for SampleExtractPlugin {
    ///     const EVENT_TYPES: &'static [EventType] = &[PLUGINEVENT_E];
    ///     const EVENT_SOURCES: &'static [&'static str] = &["dummy"];
    ///     type ExtractContext = ();
    ///     const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
    ///         field("sample.always_10", &Self::extract_sample),
    ///         field("sample.arg", &Self::extract_arg)
    ///     ];
    /// }
    ///
    ///# plugin!(SampleExtractPlugin);
    ///# extract_plugin!(SampleExtractPlugin);
    /// ```
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
        table_reader: &LazyTableReader,
        fields: &mut [ss_plugin_extract_field],
        offsets: Option<&mut ss_plugin_extract_value_offsets>,
        storage: &'a bumpalo::Bump,
    ) -> Result<(), anyhow::Error> {
        let mut context = Self::ExtractContext::default();

        let (mut offset_vec, mut length_vec) = if offsets.is_some() {
            (
                Some(bumpalo::collections::Vec::with_capacity_in(
                    fields.len(),
                    storage,
                )),
                Some(bumpalo::collections::Vec::with_capacity_in(
                    fields.len(),
                    storage,
                )),
            )
        } else {
            (None, None)
        };

        let mut any_offsets = false;

        for req in fields {
            let info = Self::EXTRACT_FIELDS
                .get(req.field_id as usize)
                .ok_or_else(|| anyhow::anyhow!("field index out of bounds"))?;

            let mut offset = if offsets.is_some() {
                ExtractByteRange::Requested
            } else {
                ExtractByteRange::NotRequested
            };

            let request = ExtractRequest::<Self> {
                context: &mut context,
                event: event_input,
                table_reader,
                offset: &mut offset,
            };

            info.func.call(self, req, request, storage)?;

            if let (Some(offsets_vec), Some(lengths_vec)) =
                (offset_vec.as_mut(), length_vec.as_mut())
            {
                let range = match offset {
                    ExtractByteRange::Found(range) => {
                        any_offsets = true;
                        range
                    }
                    _ => INVALID_RANGE,
                };
                offsets_vec.push(range.start as u32);
                lengths_vec.push(range.end.wrapping_sub(range.start) as u32);
            }
        }

        fn pointer_to_vec<T>(v: &Option<bumpalo::collections::Vec<T>>) -> *mut T {
            match v {
                None => std::ptr::null_mut(),
                Some(v) => v.as_ptr().cast_mut(),
            }
        }

        if let Some(offsets) = offsets {
            if any_offsets {
                offsets.start = pointer_to_vec(&offset_vec);
                offsets.length = pointer_to_vec(&length_vec);
            }
        }

        Ok(())
    }
}
