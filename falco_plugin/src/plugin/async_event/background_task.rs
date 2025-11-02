use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// A trivial enum to indicate the requested state of the async background task
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum RequestedState {
    Running,
    #[default]
    Stopped,
}

/// # A helper to periodically run a background task until shutdown is requested
///
/// Can be used to spawn a separate thread or as a building block for some other
/// (synchronous/blocking) abstraction.
///
/// The implementation is little more than a [`Condvar`] and some helper methods.
#[derive(Default, Debug)]
pub struct BackgroundTask {
    lock: Mutex<RequestedState>,
    cond: Condvar,
}

impl BackgroundTask {
    /// Mark the task as ready to run
    pub fn request_start(&self) -> Result<(), anyhow::Error> {
        *self
            .lock
            .lock()
            .map_err(|e| anyhow::anyhow!(e.to_string()))? = RequestedState::Running;

        Ok(())
    }

    /// Request the task to stop
    pub fn request_stop_and_notify(&self) -> Result<(), anyhow::Error> {
        *self
            .lock
            .lock()
            .map_err(|e| anyhow::anyhow!(e.to_string()))? = RequestedState::Stopped;
        self.cond.notify_one();

        Ok(())
    }

    /// Wait for a stop request for up to `timeout`
    ///
    /// Usable in a loop like:
    ///
    /// ```ignore
    /// while task.should_keep_running(timeout)? {
    ///     do_things_on_every_timeout()?;
    /// }
    /// ```
    pub fn should_keep_running(&self, timeout: Duration) -> Result<bool, anyhow::Error> {
        let (_guard, wait_res) = self
            .cond
            .wait_timeout_while(
                self.lock
                    .lock()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?,
                timeout,
                |&mut state| state == RequestedState::Running,
            )
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        Ok(wait_res.timed_out())
    }

    /// Spawn a background thread that calls `func` every `interval` until shutdown
    ///
    /// Ideally, the called closure should not block for any noticeable time, as shutdown
    /// requests are not processed while it's running.
    ///
    /// This method does not attempt to compensate for the closure running time and does not
    /// try to guarantee that it's executed exactly every `interval`. If you need precise
    /// intervals between each execution, you should start the thread yourself and calculate
    /// the timeout passed to [`BackgroundTask::should_keep_running`] every time. You will also
    /// need to handle the case when the closure takes longer than the interval:
    /// - just skip the next execution?
    /// - try to catch up by running the closure back-to-back without a delay?
    /// - return an error (and stop the background thread)?
    pub fn spawn<F>(
        self: &Arc<Self>,
        interval: Duration,
        mut func: F,
    ) -> Result<JoinHandle<Result<(), anyhow::Error>>, anyhow::Error>
    where
        F: FnMut() -> Result<(), anyhow::Error> + 'static + Send,
    {
        self.request_start()?;
        let clone = Arc::clone(self);

        Ok(std::thread::spawn(move || {
            while clone.should_keep_running(interval)? {
                func()?
            }

            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::plugin::async_event::background_task::BackgroundTask;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn test_stop_request() {
        let req = Arc::new(BackgroundTask::default());
        let counter = Arc::new(AtomicUsize::default());

        let req_clone = Arc::clone(&req);
        let counter_clone = Arc::clone(&counter);

        req.request_start().unwrap();
        let handle = std::thread::spawn(move || {
            while req_clone
                .should_keep_running(Duration::from_millis(100))
                .unwrap()
            {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            }
        });

        let start_time = Instant::now();
        std::thread::sleep(Duration::from_millis(450));
        req.request_stop_and_notify().unwrap();
        handle.join().unwrap();

        let elapsed = start_time.elapsed();
        assert_eq!(counter.load(Ordering::Relaxed), 4);

        let millis = elapsed.as_millis();
        assert!(millis >= 450);
        assert!(millis < 500);
    }

    #[test]
    fn test_spawn() {
        let req = Arc::new(BackgroundTask::default());
        let counter = Arc::new(AtomicUsize::default());
        let counter_clone = Arc::clone(&counter);

        let handle = req
            .spawn(Duration::from_millis(100), move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .unwrap();

        let start_time = Instant::now();
        std::thread::sleep(Duration::from_millis(450));
        req.request_stop_and_notify().unwrap();
        handle.join().unwrap().unwrap();

        let elapsed = start_time.elapsed();
        assert_eq!(counter.load(Ordering::Relaxed), 4);

        let millis = elapsed.as_millis();
        assert!(millis >= 450);
        assert!(millis < 500);
    }
}
