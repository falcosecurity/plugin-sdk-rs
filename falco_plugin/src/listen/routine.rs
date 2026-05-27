use crate::error::as_result::WithLastError;
use crate::error::last_error::LastError;
use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_owner_t, ss_plugin_rc, ss_plugin_routine_fn_t,
    ss_plugin_routine_state_t, ss_plugin_routine_t, ss_plugin_routine_vtable, ss_plugin_t,
};
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;

const IDLE: usize = 0;
const RUNNING: usize = 1;
const DROP_REQUESTED: usize = 2;

#[derive(Error, Debug)]
pub(super) enum ThreadPoolError {
    #[error("Missing entry {0} in thread pool operations vtable")]
    BadVtable(&'static str),
}

/// Shared coordination state between [`Routine`] and `cb_wrapper`.
///
/// This is what gets passed to the thread pool (via `Arc::into_raw`) as the
/// `ss_plugin_routine_state_t` pointer. Both [`Routine`] and the callback
/// hold `Arc` clones, so the `phase` flag is guaranteed to outlive both sides.
///
/// The `func` pointer and `dtor` are set once at creation and never modified.
/// `func` points to a heap-allocated closure (`Box::into_raw`); exactly one
/// side frees it, determined by the `phase` protocol:
///
/// - **`cb_wrapper`**: swap `RUNNING` into `phase`. If the previous value was
///   `DROP_REQUESTED`, free the closure and return 0. Otherwise, execute the
///   closure, then CAS `RUNNING → IDLE`; if that fails (`DROP_REQUESTED`),
///   free the closure.
/// - **`Routine::drop`**: swap `DROP_REQUESTED` into `phase`. If the previous
///   value was `IDLE`, free the closure. Otherwise (`RUNNING`), the callback
///   will free it on return.
struct SharedState {
    phase: AtomicUsize,
    /// Pointer to the heap-allocated closure, created via `Box::into_raw`.
    func: *mut (),
    /// Typed destructor that calls `Box::from_raw` on `func`.
    dtor: unsafe fn(*mut ()),
}

// SAFETY: `func` (a raw pointer) is the only non-Send/Sync field.
// The `phase` protocol ensures it is only accessed by one side at a time.
unsafe impl Send for SharedState {}
unsafe impl Sync for SharedState {}

/// # A handle for a routine running in the background
///
/// Returned by [`ThreadPool::subscribe`]. Dropping the handle:
/// 1. Calls `unsubscribe` (prevents future scheduling)
/// 2. Frees the closure and all captured state (immediately if the callback
///    is not running, or deferred to the callback otherwise)
#[must_use]
pub struct Routine {
    routine: *mut ss_plugin_routine_t,
    owner: *mut ss_plugin_owner_t,
    unsubscribe_fn: unsafe extern "C" fn(
        o: *mut ss_plugin_owner_t,
        r: *mut ss_plugin_routine_t,
    ) -> ss_plugin_rc,
    state: Arc<SharedState>,
}

impl std::fmt::Debug for Routine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Routine")
            .field("routine", &self.routine)
            .finish_non_exhaustive()
    }
}

// SAFETY: `routine` and `owner` are opaque framework handles passed only to
// the C API; they are never dereferenced on the Rust side.
unsafe impl Send for Routine {}
unsafe impl Sync for Routine {}

impl Drop for Routine {
    fn drop(&mut self) {
        if !self.routine.is_null() {
            // Prevents future scheduling.
            unsafe { (self.unsubscribe_fn)(self.owner, self.routine) };
        }

        // Atomically set DROP_REQUESTED and check the previous state.
        // - Was IDLE: callback is not running — free the closure now.
        // - Was RUNNING: callback will see DROP_REQUESTED when it finishes
        //   and free the closure itself.
        let prev = self.state.phase.swap(DROP_REQUESTED, Ordering::AcqRel);

        if prev == IDLE {
            unsafe {
                (self.state.dtor)(self.state.func);
            }
            // The thread pool's Arc clone (from Arc::into_raw) is not
            // reclaimed here: a callback may have already been dispatched
            // but not yet started executing. It will see DROP_REQUESTED
            // and return without touching the closure. The Arc clone is
            // a small leak (AtomicUsize + two pointers) in this case.
        }
    }
}

/// # Thread pool for managing background tasks
///
/// The thread pool operates on "routines", which are effectively closures called repeatedly
/// by the thread pool until they return [`ControlFlow::Break`].
///
/// To submit a task, pass it to [`ThreadPool::subscribe`] and store the received handle.
/// Dropping the handle automatically unsubscribes and frees the routine.
#[derive(Debug)]
pub struct ThreadPool {
    owner: *mut ss_plugin_owner_t,
    subscribe: unsafe extern "C" fn(
        o: *mut ss_plugin_owner_t,
        f: ss_plugin_routine_fn_t,
        i: *mut ss_plugin_routine_state_t,
    ) -> *mut ss_plugin_routine_t,
    unsubscribe: unsafe extern "C" fn(
        o: *mut ss_plugin_owner_t,
        r: *mut ss_plugin_routine_t,
    ) -> ss_plugin_rc,

    last_error: LastError,
}

impl ThreadPool {
    pub(super) fn try_from(
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
    ///
    /// Returns a [`Routine`]. Dropping the handle automatically unsubscribes
    /// the routine and frees the closure (immediately if idle, or after the
    /// current callback invocation finishes).
    pub fn subscribe<F>(&self, func: F) -> Result<Routine, anyhow::Error>
    where
        F: FnMut() -> ControlFlow<()> + Send + 'static,
    {
        unsafe extern "C" fn cb_wrapper<F>(
            _plugin: *mut ss_plugin_t,
            data: *mut ss_plugin_routine_state_t,
        ) -> ss_plugin_bool
        where
            F: FnMut() -> ControlFlow<()> + Send + 'static,
        {
            // Reconstruct the Arc from the raw pointer. Only cb_wrapper
            // touches this refcount — Routine::drop never reclaims it.
            // If we return Continue (1), we forget it to preserve the
            // refcount for the next call. Otherwise we let it drop.
            let arc = unsafe { Arc::from_raw(data as *const SharedState) };

            // Swap RUNNING into phase. If previous value was DROP_REQUESTED,
            // the handle has been dropped and the closure already freed.
            let prev = arc.phase.swap(RUNNING, Ordering::AcqRel);
            if prev == DROP_REQUESTED {
                // arc drops here, reclaiming the refcount.
                return 0;
            }

            // We hold RUNNING — safe to access the closure.
            let f = unsafe { &mut *(arc.func as *mut F) };
            let result = match f() {
                ControlFlow::Continue(()) => 1,
                ControlFlow::Break(()) => 0,
            };

            // Try to go back to IDLE. If drop set DROP_REQUESTED, we free.
            if arc
                .phase
                .compare_exchange(RUNNING, IDLE, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // DROP_REQUESTED: free the closure.
                unsafe {
                    (arc.dtor)(arc.func);
                }
                // arc drops here, reclaiming the refcount.
                return 0;
            }

            if result == 1 {
                // Continue — preserve the refcount for the next call.
                std::mem::forget(arc);
            }
            // else: Break — arc drops here, reclaiming the refcount.

            result
        }

        unsafe fn cb_drop<F>(ptr: *mut ()) {
            unsafe {
                drop(Box::from_raw(ptr as *mut F));
            }
        }

        let callback = Some(
            cb_wrapper::<F>
                as unsafe extern "C" fn(
                    _plugin: *mut ss_plugin_t,
                    data: *mut ss_plugin_routine_state_t,
                ) -> ss_plugin_bool,
        );

        let func_ptr = Box::into_raw(Box::new(func));

        let state = Arc::new(SharedState {
            phase: AtomicUsize::new(IDLE),
            func: func_ptr as *mut (),
            dtor: cb_drop::<F>,
        });

        // Give the thread pool its own Arc clone via into_raw.
        let tp_clone = Arc::clone(&state);
        let raw_ptr = Arc::into_raw(tp_clone);

        let ptr = unsafe {
            (self.subscribe)(
                self.owner,
                callback,
                raw_ptr as *mut ss_plugin_routine_state_t,
            )
        };

        if ptr.is_null() {
            // Reclaim the thread pool's Arc clone.
            unsafe {
                Arc::from_raw(raw_ptr);
            }
            // Free the closure.
            unsafe {
                drop(Box::from_raw(func_ptr));
            }
            Err(anyhow::anyhow!("Failed to subscribe function")).with_last_error(&self.last_error)
        } else {
            Ok(Routine {
                routine: ptr,
                owner: self.owner,
                unsubscribe_fn: self.unsubscribe,
                state,
            })
        }
    }
}
