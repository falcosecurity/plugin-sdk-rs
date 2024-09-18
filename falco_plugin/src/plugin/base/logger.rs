use falco_plugin_api::{
    ss_plugin_log_severity, ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_DEBUG,
    ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_ERROR, ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_INFO,
    ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_TRACE,
    ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_WARNING, ss_plugin_owner_t,
};
use log::{Level, Log, Metadata, Record};
use std::ffi::{c_char, CString};

#[cfg(debug_assertions)]
use std::borrow::Cow;
use std::sync::RwLock;

pub(super) struct FalcoPluginLoggerImpl {
    pub(super) owner: *mut ss_plugin_owner_t,
    pub(super) logger_fn: unsafe extern "C-unwind" fn(
        o: *mut ss_plugin_owner_t,
        component: *const c_char,
        msg: *const c_char,
        sev: ss_plugin_log_severity,
    ),
}
unsafe impl Send for FalcoPluginLoggerImpl {}
unsafe impl Sync for FalcoPluginLoggerImpl {}

pub(super) struct FalcoPluginLogger {
    pub(super) inner: RwLock<Option<FalcoPluginLoggerImpl>>,
}

impl Log for FalcoPluginLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let severity = match record.level() {
            Level::Error => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_ERROR,
            Level::Warn => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_WARNING,
            Level::Info => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_INFO,
            Level::Debug => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_DEBUG,
            Level::Trace => ss_plugin_log_severity_SS_PLUGIN_LOG_SEV_TRACE,
        };

        #[cfg(not(debug_assertions))]
        let msg = format!("[{}] {}", record.level(), record.args());

        #[cfg(debug_assertions)]
        let msg = {
            let loc = record
                .file()
                .zip(record.line())
                .map(|(f, l)| Cow::Owned(format!("{}:{}", f, l)))
                .unwrap_or_else(|| Cow::Borrowed(record.target()));
            format!("{}[{}] {}", loc, record.level(), record.args())
        };

        let logger_impl = self.inner.read().unwrap();
        if let Some(ref logger_impl) = *logger_impl {
            if let Ok(msg) = CString::new(msg) {
                unsafe {
                    (logger_impl.logger_fn)(
                        logger_impl.owner,
                        std::ptr::null(),
                        msg.as_ptr(),
                        severity,
                    )
                }
            }
        } else {
            eprintln!("{msg}")
        }
    }

    fn flush(&self) {}
}

pub(crate) static FALCO_LOGGER: FalcoPluginLogger = FalcoPluginLogger {
    inner: RwLock::new(None),
};
