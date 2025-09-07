//! # Capture listening plugins
//!
//! Plugins with capture listening capability can receive notifications whenever a capture is
//! started or stopped. Note that a capture may be stopped and restarted multiple times
//! over the lifetime of a plugin.
//!
//! ## Background tasks
//!
//! Capture listening plugins receive a reference to a thread pool, which can be used to submit
//! "routines" (tasks running in a separate thread, effectively).
//!
//! *Note* there is no built-in mechanism to stop a running routine, so you should avoid doing this
//! in the routine:
//! ```ignore
//! loop {
//!     do_something();
//!     std::thread::sleep(some_time);
//! }
//! ```
//!
//! Instead, have your routine just do a single iteration and request a rerun from the scheduler:
//! ```ignore
//! do_something();
//! std::thread::sleep(some_time)
//! std::ops::ControlFlow::Continue(())
//! ```
//!
//! If you insist on using an infinite loop inside a routine, consider using e.g.
//! [`BackgroundTask`](crate::async_event::BackgroundTask) to manage the lifetime of the routine.
//!
//! For your plugin to support event parsing, you will need to implement the [`CaptureListenPlugin`]
//! trait and invoke the [`capture_listen_plugin`](crate::capture_listen_plugin) macro, for example:
//!
//! ```
//!# use std::ffi::CStr;
//!# use std::time::Duration;
//! use falco_plugin::anyhow::Error;
//! use falco_plugin::base::Plugin;
//! use falco_plugin::{capture_listen_plugin, plugin};
//! use falco_plugin::listen::{CaptureListenInput, CaptureListenPlugin, Routine};
//!# use falco_plugin::tables::TablesInput;
//!# use log;
//!
//! struct MyListenPlugin {
//!     tasks: Vec<Routine>,
//! }
//!
//! impl Plugin for MyListenPlugin {
//!     // ...
//! #    const NAME: &'static CStr = c"sample-plugin-rs";
//! #    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
//! #    const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
//! #    const CONTACT: &'static CStr = c"you@example.com";
//! #    type ConfigType = ();
//! #
//! #    fn new(input: Option<&TablesInput>, config: Self::ConfigType)
//! #        -> Result<Self, Error> {
//! #        Ok(MyListenPlugin {
//! #             tasks: Vec::new(),
//! #        })
//! #    }
//! }
//!
//! impl CaptureListenPlugin for MyListenPlugin {
//!     fn capture_open(&mut self, listen_input: &CaptureListenInput) -> Result<(), Error> {
//!         log::info!("Capture started");
//!         self.tasks.push(listen_input.thread_pool.subscribe(|| {
//!             log::info!("Doing stuff in the background");
//!             std::thread::sleep(Duration::from_millis(500));
//!             std::ops::ControlFlow::Continue(())
//!         })?);
//!
//!         Ok(())
//!     }
//!
//! fn capture_close(&mut self, listen_input: &CaptureListenInput) -> Result<(), Error> {
//!         log::info!("Capture stopped");
//!         for routine in self.tasks.drain(..) {
//!             listen_input.thread_pool.unsubscribe(&routine)?;
//!         }
//!
//!         Ok(())
//!     }
//! }
//!
//! plugin!(MyListenPlugin);
//! capture_listen_plugin!(MyListenPlugin);
//! ```

use crate::base::Plugin;
use crate::listen::wrappers::CaptureListenPluginExported;
use crate::plugin::error::last_error::LastError;
use crate::tables::LazyTableReader;
use crate::tables::LazyTableWriter;
use falco_plugin_api::ss_plugin_capture_listen_input;

mod routine;
#[doc(hidden)]
pub mod wrappers;

pub use routine::{Routine, ThreadPool};

/// Support for capture listening plugins
pub trait CaptureListenPlugin: Plugin + CaptureListenPluginExported {
    /// # Capture open notification
    ///
    /// This method gets called whenever the capture is started
    fn capture_open(&mut self, listen_input: &CaptureListenInput) -> Result<(), anyhow::Error>;

    /// # Capture close notification
    ///
    /// This method gets called whenever the capture is stopped
    fn capture_close(&mut self, listen_input: &CaptureListenInput) -> Result<(), anyhow::Error>;
}

/// # The input to a capture listening plugin
///
/// It has two fields containing the vtables needed to access tables imported through
/// the [tables API](`crate::tables`), as well as a [`ThreadPool`] to run tasks
/// in the background.
#[derive(Debug)]
pub struct CaptureListenInput<'t> {
    /// Accessors to the thread pool for submitting routines to
    pub thread_pool: ThreadPool,
    /// Accessors to read table entries
    pub reader: LazyTableReader<'t>,
    /// Accessors to modify table entries
    pub writer: LazyTableWriter<'t>,
}

impl CaptureListenInput<'_> {
    unsafe fn try_from(
        value: *const ss_plugin_capture_listen_input,
        last_error: LastError,
    ) -> Result<Self, anyhow::Error> {
        let input = unsafe {
            value
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Got null event parse input"))?
        };

        let thread_pool = ThreadPool::try_from(input.owner, input.routine, last_error.clone())?;

        let reader = unsafe {
            input
                .table_reader_ext
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Got null reader vtable"))?
        };
        let writer = unsafe {
            input
                .table_writer_ext
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Got null writer vtable"))?
        };

        let reader = LazyTableReader::new(reader, last_error.clone());
        let writer = LazyTableWriter::try_from(writer, last_error)?;

        Ok(Self {
            thread_pool,
            reader,
            writer,
        })
    }
}
