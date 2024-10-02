use falco_plugin::anyhow::{self, Error};
use falco_plugin::async_event::BackgroundTask;
use falco_plugin::base::Plugin;
use falco_plugin::extract::EventInput;
use falco_plugin::listen::{CaptureListenInput, CaptureListenPlugin, Routine};
use falco_plugin::source::{EventBatch, SourcePlugin, SourcePluginInstance};
use falco_plugin::tables::TablesInput;
use falco_plugin::{static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct DummyPlugin {
    start_time: std::time::Instant,
    task_state: Arc<BackgroundTask>,
    task: Option<Routine>,
    counter: Arc<AtomicUsize>,
}

impl Plugin for DummyPlugin {
    const NAME: &'static CStr = c"dummy";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"dummy async plugin";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self {
            start_time: std::time::Instant::now(),
            task_state: Default::default(),
            task: None,
            counter: Default::default(),
        })
    }
}

struct DummyPluginInstance;

impl SourcePluginInstance for DummyPluginInstance {
    type Plugin = DummyPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        _batch: &mut EventBatch,
    ) -> Result<(), Error> {
        std::thread::sleep(Duration::from_millis(20));
        let count = plugin.counter.load(Ordering::Relaxed);
        if count >= 10 {
            Err(anyhow::anyhow!("this plugin does nothing").context(FailureReason::Eof))
        } else if plugin.start_time.elapsed() > Duration::from_millis(1200) {
            Err(anyhow::anyhow!("did not get 10 pings from background task")
                .context(FailureReason::Failure))
        } else {
            Err(anyhow::anyhow!("this plugin does nothing").context(FailureReason::Timeout))
        }
    }
}

impl SourcePlugin for DummyPlugin {
    type Instance = DummyPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"dummy";
    const PLUGIN_ID: u32 = 1111;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(DummyPluginInstance)
    }

    fn event_to_string(&mut self, _event: &EventInput) -> Result<CString, Error> {
        Ok(CString::from(c"what event?"))
    }
}

impl CaptureListenPlugin for DummyPlugin {
    fn capture_open(&mut self, listen_input: &CaptureListenInput) -> Result<(), Error> {
        self.task_state.request_start()?;

        let counter = Arc::clone(&self.counter);
        let task_state = Arc::clone(&self.task_state);
        self.task = Some(listen_input.thread_pool.subscribe(move || {
            while task_state
                .should_keep_running(Duration::from_millis(100))
                .unwrap()
            {
                counter.fetch_add(1, Ordering::Relaxed);
            }

            ControlFlow::Break(())
        })?);

        Ok(())
    }

    fn capture_close(&mut self, listen_input: &CaptureListenInput) -> Result<(), Error> {
        if let Some(task) = self.task.take() {
            listen_input.thread_pool.unsubscribe(&task)?;
        }
        self.task_state.request_stop_and_notify()?;

        Ok(())
    }
}

static_plugin!(DUMMY_PLUGIN_API = DummyPlugin);

#[cfg(test)]
mod tests {
    use falco_plugin::base::Plugin;
    use falco_plugin_tests::{
        init_plugin, instantiate_tests, CapturingTestDriver, ScapStatus, TestDriver,
    };

    fn test_listen<D: TestDriver>() {
        let (driver, _plugin) = init_plugin::<D>(super::DUMMY_PLUGIN_API, c"").unwrap();
        let mut driver = driver.start_capture(super::DummyPlugin::NAME, c"").unwrap();

        loop {
            let event = driver.next_event();
            match event {
                Ok(_) => continue,
                Err(ScapStatus::Timeout) => continue,
                Err(ScapStatus::Eof) => break,
                Err(e) => panic!("Got {:?}", e),
            }
        }
    }

    instantiate_tests!(test_listen);
}
