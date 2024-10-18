pub mod routine;
#[doc(hidden)]
pub mod wrappers;

use crate::base::Plugin;
use crate::listen::ThreadPool;
use crate::plugin::error::last_error::LastError;
use crate::plugin::tables::vtable::writer::LazyTableWriter;
use crate::tables::LazyTableReader;
use falco_plugin_api::ss_plugin_capture_listen_input;

/// Support for capture listening plugins
pub trait CaptureListenPlugin: Plugin {
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

impl<'t> CaptureListenInput<'t> {
    pub(in crate::plugin::listen) unsafe fn try_from(
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
