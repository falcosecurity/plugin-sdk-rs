//! # Asynchronous event support
//!
//! Plugins with async events capability can enrich an event stream from a given source (not
//! necessarily implemented by itself) by injecting events asynchronously in the stream. Such
//! a feature can be used for implementing notification systems or recording state transitions
//! in the event-driven model of the Falcosecurity libraries, so that they can be available to other
//! components at runtime or when the event stream is replayed through a capture file.
//!
//! For example, the Falcosecurity libraries leverage this feature internally to implement metadata
//! enrichment systems such as the one related to container runtimes. In that case, the libraries
//! implement asynchronous jobs responsible for retrieving such information externally outside
//! the main event processing loop so that it's non-blocking. The worker jobs produce a notification
//! event every time a new container is detected and inject it asynchronously in the system event
//! stream to be later processed for state updates and for evaluating Falco rules.
//!
//! For your plugin to support asynchronous events, you will need to implement the [`AsyncEventPlugin`]
//! trait and invoke the [`async_event_plugin`](crate::async_event_plugin) macro, for example:
//!
//! ```
//! use std::ffi::{CStr, CString};
//! use std::sync::Arc;
//! use std::thread::JoinHandle;
//! use falco_plugin::anyhow::Error;
//! use falco_plugin::event::events::Event;
//! use falco_plugin::event::events::EventMetadata;
//! use falco_plugin::base::Plugin;
//! use falco_plugin::{async_event_plugin, plugin};
//! use falco_plugin::async_event::{
//!     AsyncEventPlugin,
//!     AsyncHandler,
//!     BackgroundTask};
//! use falco_plugin::tables::TablesInput;
//!
//! struct MyAsyncPlugin {
//!     task: Arc<BackgroundTask>,
//!     thread: Option<JoinHandle<Result<(), Error>>>,
//! }
//!
//! impl Plugin for MyAsyncPlugin {
//!     // ...
//! #    const NAME: &'static CStr = c"sample-plugin-rs";
//! #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
//! #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
//! #    const CONTACT: &'static CStr = c"you@example.com";
//! #    type ConfigType = ();
//! #
//! #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
//! #        -> Result<Self, Error> {
//! #        Ok(MyAsyncPlugin {
//! #            task: Arc::new(Default::default()),
//! #            thread: None,
//! #        })
//! #    }
//! }
//!
//! impl AsyncEventPlugin for MyAsyncPlugin {
//!     const ASYNC_EVENTS: &'static [&'static str] = &[]; // generate any async events
//!     const EVENT_SOURCES: &'static [&'static str] = &[]; // attach to all event sources
//!
//!     fn start_async(&mut self, handler: AsyncHandler) -> Result<(), Error> {
//!         // stop the thread if it was already running
//!         if self.thread.is_some() {
//!            self.stop_async()?;
//!         }
//!
//!         // start a new thread
//!         // waiting up to 100ms between events for the stop request
//!         self.thread = Some(self.task.spawn(std::time::Duration::from_millis(100), move || {
//!             // submit an async event to the main event loop
//!             handler.emit(Self::async_event(c"sample_async", b"hello"))?;
//!             Ok(())
//!         })?);
//!         Ok(())
//!     }
//!
//!     fn stop_async(&mut self) -> Result<(), Error> {
//!         self.task.request_stop_and_notify()?;
//!         let Some(handle) = self.thread.take() else {
//!             return Ok(());
//!         };
//!
//!         match handle.join() {
//!             Ok(res) => res,
//!             Err(e) => std::panic::resume_unwind(e),
//!         }
//!     }
//! }
//!
//! plugin!(MyAsyncPlugin);
//! async_event_plugin!(MyAsyncPlugin);
//! ```

use crate::async_event::wrappers::AsyncPluginExported;
use crate::base::Plugin;
use falco_event::events::Event;

mod async_handler;
mod background_task;
#[doc(hidden)]
pub mod wrappers;

pub use crate::event::AsyncEvent;
pub use async_handler::AsyncHandler;
pub use background_task::BackgroundTask;

/// Support for asynchronous event plugins
pub trait AsyncEventPlugin: Plugin + AsyncPluginExported {
    /// # Event names coming from this plugin
    ///
    /// This constant contains a list describing the name list of all asynchronous events
    /// that this plugin is capable of pushing into a live event stream. The framework rejects
    /// async events produced by a plugin if their name is not on the name list returned by this
    /// function.
    const ASYNC_EVENTS: &'static [&'static str];
    /// # Event sources to attach asynchronous events to
    ///
    /// This constant contains a list describing the event sources for which this plugin
    /// is capable of injecting async events in the event stream of a capture.
    ///
    /// This is optional--if NULL or an empty array, then async events produced by this plugin will
    /// be injected in the event stream of any data source.
    ///
    /// **Note**: one notable event source is called `syscall`
    const EVENT_SOURCES: &'static [&'static str];

    /// # Start asynchronous event generation
    ///
    /// When this method is called, your plugin should start whatever background mechanism
    /// is necessary (e.g. spawn a separate thread) and use the [`AsyncHandler::emit`] method
    /// to inject events to the main event loop.
    ///
    /// **Note**: you must provide a mechanism to shut down the thread upon a call to [`AsyncEventPlugin::stop_async`].
    /// This may involve e.g. a [`std::sync::Condvar`] that's checked via [`std::sync::Condvar::wait_timeout`]
    /// by the thread.
    ///
    /// **Note**: one notable event source is called `syscall`
    fn start_async(&mut self, handler: AsyncHandler) -> Result<(), anyhow::Error>;

    /// # Stop asynchronous event generation
    ///
    /// When this method is called, your plugin must stop the background mechanism started by
    /// [`AsyncEventPlugin::start_async`] and wait for it to finish (no calls to [`AsyncHandler::emit`]
    /// are permitted after this method returns).
    ///
    /// **Note**: [`AsyncEventPlugin::start_async`] can be called again, with a different [`AsyncHandler`].
    fn stop_async(&mut self) -> Result<(), anyhow::Error>;

    /// # Dump the plugin state as a series of async events
    ///
    /// When this method is called, your plugin may save its state via a series of async events
    /// that will be replayed when a capture file is loaded.
    ///
    /// The default implementation does nothing.
    fn dump_state(&mut self, _handler: AsyncHandler) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// # A helper method to create an asynchronous event
    fn async_event<'a>(
        name: &'a std::ffi::CStr,
        data: &'a [u8],
    ) -> Event<AsyncEvent<'a, &'a [u8]>> {
        let event = AsyncEvent {
            plugin_id: 0, // gets populated by the framework, shall be None
            name,
            data,
        };

        let metadata = falco_event::events::EventMetadata::default();

        Event {
            metadata,
            params: event,
        }
    }
}
