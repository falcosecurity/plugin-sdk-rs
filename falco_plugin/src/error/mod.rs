pub mod as_result;
pub mod ffi_result;
pub mod last_error;

use thiserror::Error;

use falco_plugin_api::ss_plugin_rc;
/// # Failure reason to report to the plugin framework
#[derive(Debug, Clone, Copy, Error)]
pub enum FailureReason {
    /// # General failure
    ///
    /// This failure reason indicates an actual error that occurred and may end up with
    /// the Falco process shutting down (after a long chain of error propagation).
    ///
    /// All [`Result`] values without a specific reason set default to this value
    #[error("failure")]
    Failure,

    /// # Timeout
    ///
    /// This is not an actual failure but an indication that there's no data available yet.
    /// This code is meaningful in source plugins, in the [`next_batch`](`crate::source::SourcePluginInstance::next_batch`)
    /// method.
    ///
    /// The framework will retry the call at a later time.
    #[error("timeout")]
    Timeout,

    /// # End of data
    ///
    /// This is not an actual failure but an indication that there will be no more data.
    /// This code is meaningful in source plugins, in the [`next_batch`](`crate::source::SourcePluginInstance::next_batch`)
    /// method.
    ///
    /// The framework will stop the event collection process cleanly.
    #[error("end of data")]
    Eof,

    /// # Not supported
    ///
    /// This code indicates that an operation is not supported.
    #[error("not supported")]
    NotSupported,
}

impl From<FailureReason> for ss_plugin_rc {
    fn from(value: FailureReason) -> Self {
        match value {
            FailureReason::Failure => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_FAILURE,
            FailureReason::Timeout => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_TIMEOUT,
            FailureReason::Eof => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_EOF,
            FailureReason::NotSupported => falco_plugin_api::ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED,
        }
    }
}
