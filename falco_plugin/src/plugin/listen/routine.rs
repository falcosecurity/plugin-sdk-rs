use crate::plugin::error::as_result::{AsResult, WithLastError};
use crate::plugin::error::last_error::LastError;
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_owner_t, ss_plugin_rc, ss_plugin_routine_fn_t,
    ss_plugin_routine_state_t, ss_plugin_routine_t, ss_plugin_routine_vtable, ss_plugin_t,
};
use std::ops::ControlFlow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ThreadPoolError {
    #[error("Missing entry {0} in thread pool operations vtable")]
    BadVtable(&'static str),
}

/// # A handle for a routine running in the background
///
/// This is an opaque object, coming from [`ThreadPool::subscribe`], that will drop
/// the wrapped closure when dropped itself.
///
/// *Note*: it's your responsibility to hold on to the handle as long as the closure
/// may be called. Sadly, our capabilities are limited here, so one approach might be
/// to skip the destructor call with e.g. [`std::mem::ManuallyDrop`] and dropping the wrapper.
/// This will leak memory but will be guaranteed safe.
#[derive(Debug)]
#[must_use]
pub struct Routine {
    routine: *mut ss_plugin_routine_t,
    state: *mut ss_plugin_routine_state_t,
    dtor: unsafe fn(*mut ss_plugin_routine_state_t) -> (),
}

impl Drop for Routine {
    fn drop(&mut self) {
        unsafe { (self.dtor)(self.state) }
    }
}

/// # Thread pool for managing background tasks
///
/// The thread pool operates on "routines", which are effectively closures called repeatedly
/// by the thread pool until they return [`ControlFlow::Break`].
///
/// To submit a task, pass it to [`ThreadPool::subscribe`] and store the received handle.
/// To cancel a task, pass its handle to [`ThreadPool::unsubscribe`].
#[derive(Debug)]
pub struct ThreadPool {
    owner: *mut ss_plugin_owner_t,
    subscribe: unsafe extern "C-unwind" fn(
        o: *mut ss_plugin_owner_t,
        f: ss_plugin_routine_fn_t,
        i: *mut ss_plugin_routine_state_t,
    ) -> *mut ss_plugin_routine_t,
    unsubscribe: unsafe extern "C-unwind" fn(
        o: *mut ss_plugin_owner_t,
        r: *mut ss_plugin_routine_t,
    ) -> ss_plugin_rc,

    last_error: LastError,
}

impl ThreadPool {
    pub(in crate::plugin::listen) fn try_from(
        owner: *mut ss_plugin_owner_t,
        vtable: *const ss_plugin_routine_vtable,
        last_error: LastError,
    ) -> Result<Self, ThreadPoolError> {
        let vtable = unsafe { vtable.as_ref() }.ok_or(ThreadPoolError::BadVtable("vtable"))?;

        let subscribe = vtable
            .subscribe
            .ok_or(ThreadPoolError::BadVtable("subscribe"))?;
        let unsubscribe = vtable
            .unsubscribe
            .ok_or(ThreadPoolError::BadVtable("unsubscribe"))?;

        Ok(Self {
            owner,
            subscribe,
            unsubscribe,
            last_error,
        })
    }

    /// Run a task in a background thread
    pub fn subscribe<F>(&self, func: F) -> Result<Routine, anyhow::Error>
    where
        F: FnMut() -> ControlFlow<()> + Send + 'static,
    {
        unsafe extern "C-unwind" fn cb_wrapper<F>(
            _plugin: *mut ss_plugin_t,
            data: *mut ss_plugin_routine_state_t,
        ) -> ss_plugin_bool
        where
            F: FnMut() -> ControlFlow<()> + Send + 'static,
        {
            let f = data as *mut F;
            unsafe {
                match (*f)() {
                    ControlFlow::Continue(()) => 1,
                    ControlFlow::Break(()) => 0,
                }
            }
        }

        unsafe fn cb_drop<F>(data: *mut ss_plugin_routine_state_t) {
            let cb = data as *mut F;
            let _ = Box::from_raw(cb);
        }

        let callback = Some(
            cb_wrapper::<F>
                as unsafe extern "C-unwind" fn(
                    _plugin: *mut ss_plugin_t,
                    data: *mut ss_plugin_routine_state_t,
                ) -> ss_plugin_bool,
        );

        let boxed_func = Box::new(func);
        let boxed_func = Box::into_raw(boxed_func) as *mut ss_plugin_routine_state_t;

        let ptr = unsafe { (self.subscribe)(self.owner, callback, boxed_func) };

        if ptr.is_null() {
            Err(anyhow::anyhow!("Failed to subscribe function")).with_last_error(&self.last_error)
        } else {
            Ok(Routine {
                routine: ptr,
                state: boxed_func,
                dtor: cb_drop::<F>,
            })
        }
    }

    /// Cancel a task running in a background thread
    ///
    /// *Note*: this does not kill a running task, only prevent it from being scheduled again
    pub fn unsubscribe(&self, routine: &Routine) -> Result<(), anyhow::Error> {
        unsafe {
            (self.unsubscribe)(self.owner, routine.routine)
                .as_result()
                .with_last_error(&self.last_error)
        }
    }
}
