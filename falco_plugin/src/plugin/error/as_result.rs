use crate::plugin::error::last_error::LastError;
use crate::FailureReason;
use anyhow::Context;
use falco_plugin_api::ss_plugin_rc;

pub trait AsResult {
    fn as_result(&self) -> Result<(), FailureReason>;
}

impl AsResult for ss_plugin_rc {
    fn as_result(&self) -> Result<(), FailureReason> {
        use falco_plugin_api as b;
        match *self {
            b::ss_plugin_rc_SS_PLUGIN_SUCCESS => Ok(()),
            b::ss_plugin_rc_SS_PLUGIN_FAILURE => Err(FailureReason::Failure),
            b::ss_plugin_rc_SS_PLUGIN_TIMEOUT => Err(FailureReason::Timeout),
            b::ss_plugin_rc_SS_PLUGIN_EOF => Err(FailureReason::Timeout),
            b::ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED => Err(FailureReason::NotSupported),
            _ => Err(FailureReason::Failure),
        }
    }
}

pub trait WithLastError {
    type Decorated;

    fn with_last_error(self, last_error: &LastError) -> Self::Decorated;
}

impl<T, E> WithLastError for Result<T, E>
where
    E: Into<anyhow::Error>,
    Self: Context<T, E>,
{
    type Decorated = anyhow::Result<T>;

    fn with_last_error(self, last_error: &LastError) -> Self::Decorated {
        match self {
            Ok(ok) => Ok(ok),
            Err(_) => {
                let Some(msg) = last_error.get() else {
                    return self.map_err(|e| e.into());
                };

                self.context(msg)
            }
        }
    }
}
