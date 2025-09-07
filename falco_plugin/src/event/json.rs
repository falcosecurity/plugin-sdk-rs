use crate::event::EventSource;
use falco_event::fields::{FromBytes, FromBytesError, ToBytes};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cell::RefCell;
use std::fmt::Debug;
use std::io::Write;

/// A wrapper that enables JSON-encoded event payloads in [`crate::event::AsyncEvent`] and [`crate::event::PluginEvent`]
///
/// To store an arbitrary type as JSON inside the payload, make sure the data implements
/// `Serialize` and `Deserialize` from `serde` and use `JsonPayload<T>` as the payload type:
/// ```
/// use falco_event::events::{AnyEventPayload, RawEvent};
/// use falco_plugin::event::{EventSource, JsonPayload, PluginEvent};
/// use falco_plugin::event::events::Event;
///
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct MyEvent {
///     param1: u32,
///     param2: u32,
/// }
///
/// impl EventSource for MyEvent {
///     const SOURCE: Option<&'static str> = Some("my_plugin");
/// }
///
///# trait FakePluginTrait {
///#     type Event<'a>: AnyEventPayload + TryFrom<&'a RawEvent<'a>> where Self: 'a;
///# }
///# struct FakePlugin;
///# impl FakePluginTrait for FakePlugin {
/// // in a plugin trait implementation:
/// type Event<'a> = Event<PluginEvent<JsonPayload<MyEvent>>>;
///# }
/// ```
///
/// *Note*: this SDK provides JSON support since it's already necessary to talk
/// to the Falco Plugin API. JSON is not a good choice for high-volume events, as it takes
/// a lot of space and is pretty slow, compared to binary formats. See the source
/// of `plugin::event:json` for what is needed to support a different serialization format
/// and consider using e.g. [bincode](https://crates.io/crates/bincode) instead.
pub struct JsonPayload<T> {
    inner: T,
    serialized: RefCell<Option<Result<Vec<u8>, std::io::Error>>>,
}

impl<T> Debug for JsonPayload<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        T::fmt(&self.inner, f)
    }
}

impl<T> JsonPayload<T> {
    /// Create a [`JsonPayload`] object from any data
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            serialized: RefCell::new(None),
        }
    }

    /// Get a reference to the data inside
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the data inside
    pub fn get_mut(&mut self) -> &mut T {
        self.serialized.replace(None);
        &mut self.inner
    }

    /// Return the wrapped data, dropping the wrapper
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> JsonPayload<T>
where
    T: Serialize,
{
    fn update_serialized(&self) {
        if self.serialized.borrow().is_none() {
            self.serialized.replace(Some(
                serde_json::to_vec(&self.inner).map_err(std::io::Error::from),
            ));
        }
    }
}

impl<'a, T> FromBytes<'a> for JsonPayload<T>
where
    T: DeserializeOwned,
{
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, FromBytesError> {
        let value: T = serde_json::from_slice(buf).map_err(|e| FromBytesError::Other(e.into()))?;
        Ok(Self::new(value))
    }
}

impl<T> ToBytes for JsonPayload<T>
where
    T: Serialize,
{
    fn binary_size(&self) -> usize {
        self.update_serialized();
        match self.serialized.borrow().as_ref().unwrap() {
            Ok(v) => v.len(),
            Err(_) => 0,
        }
    }

    fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        self.update_serialized();
        match self.serialized.take().unwrap() {
            Ok(v) => {
                let ret = v.as_slice().write(writer).map(|_| ());
                self.serialized.replace(Some(Ok(v)));
                ret
            }
            Err(e) => Err(e),
        }
    }

    fn default_repr() -> impl ToBytes {
        &[] as &[u8]
    }
}

impl<T> EventSource for JsonPayload<T>
where
    T: EventSource,
{
    const SOURCE: Option<&'static str> = T::SOURCE;
}
