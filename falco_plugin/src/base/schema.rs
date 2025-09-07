use schemars::{schema_for, JsonSchema};
use serde::de::DeserializeOwned;
use std::any::TypeId;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::sync::Mutex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SchemaError {
    #[error("JSON deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type SchemaResult<T> = Result<T, SchemaError>;

pub enum ConfigSchemaType {
    None,
    Json(&'static CStr),
}

/// A wrapper to mark a configuration schema as JSON-encoded
///
/// Using this type as the configuration type in your plugin automatically generates
/// the schema describing the configuration format.
#[derive(Debug)]
pub struct Json<T: JsonSchema + DeserializeOwned>(pub T);

pub trait ConfigSchema: Sized {
    fn get_schema() -> ConfigSchemaType;

    fn from_str(s: &str) -> SchemaResult<Self>;
}

impl<T: JsonSchema + DeserializeOwned + 'static> ConfigSchema for Json<T> {
    fn get_schema() -> ConfigSchemaType {
        static CONFIG_SCHEMA: Mutex<BTreeMap<TypeId, CString>> = Mutex::new(BTreeMap::new());

        let ty = TypeId::of::<Self>();
        let mut schema_map = CONFIG_SCHEMA.lock().unwrap();
        // Safety:
        //
        // we only generate the string once and never change or delete it
        // so the pointer should remain valid for the static lifetime
        // hence the dance of converting a reference to a raw pointer and back
        // to erase the lifetime
        let ptr = unsafe {
            CStr::from_ptr(
                schema_map
                    .entry(ty)
                    .or_insert_with(|| {
                        let schema = schema_for!(T);
                        let schema = serde_json::to_string_pretty(&schema)
                            .expect("failed to serialize config schema");
                        CString::new(schema.into_bytes())
                            .expect("failed to add NUL to config schema")
                    })
                    .as_ptr(),
            )
        };

        ConfigSchemaType::Json(ptr)
    }

    fn from_str(s: &str) -> SchemaResult<Self> {
        let target: T = serde_json::from_str(s)?;
        Ok(Json(target))
    }
}

impl ConfigSchema for String {
    fn get_schema() -> ConfigSchemaType {
        ConfigSchemaType::None
    }

    fn from_str(s: &str) -> SchemaResult<Self> {
        Ok(s.to_string())
    }
}

impl ConfigSchema for () {
    fn get_schema() -> ConfigSchemaType {
        ConfigSchemaType::None
    }

    fn from_str(_: &str) -> SchemaResult<Self> {
        Ok(())
    }
}
