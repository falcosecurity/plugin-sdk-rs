use std::sync::Arc;

#[cfg(all(feature = "thread-safe-tables", not(miri)))]
use parking_lot::RawRwLock as LockImpl;

#[cfg(all(feature = "thread-safe-tables", miri))]
use miri_lock::StdRawRwLock as LockImpl;

#[cfg(not(feature = "thread-safe-tables"))]
use refcell_lock_api::raw::CellRwLock as LockImpl;

/// A [`lock_api::RawRwLock`] implementation backed by `std::sync` primitives.
///
/// `parking_lot`'s implementation uses integer-to-pointer casts that Miri warns about
/// (see <https://doc.rust-lang.org/nightly/std/ptr/fn.with_exposed_provenance.html>).
/// When running under Miri we therefore substitute `parking_lot` with this implementation,
/// which relies only on `std::sync::Mutex` and `std::sync::Condvar` — both of which have
/// native Miri support.
#[cfg(all(feature = "thread-safe-tables", miri))]
mod miri_lock {
    use std::sync::{Condvar, Mutex};

    struct State {
        readers: u32,
        writing: bool,
    }

    #[allow(missing_debug_implementations)]
    pub struct StdRawRwLock {
        state: Mutex<State>,
        cvar: Condvar,
    }

    unsafe impl lock_api::RawRwLock for StdRawRwLock {
        #[allow(clippy::declare_interior_mutable_const)]
        const INIT: Self = Self {
            state: Mutex::new(State {
                readers: 0,
                writing: false,
            }),
            cvar: Condvar::new(),
        };

        type GuardMarker = lock_api::GuardSend;

        fn lock_shared(&self) {
            let mut state = self.state.lock().unwrap();
            loop {
                if !state.writing {
                    state.readers += 1;
                    return;
                }
                state = self.cvar.wait(state).unwrap();
            }
        }

        fn try_lock_shared(&self) -> bool {
            let mut state = self.state.lock().unwrap();
            if !state.writing {
                state.readers += 1;
                true
            } else {
                false
            }
        }

        unsafe fn unlock_shared(&self) {
            let mut state = self.state.lock().unwrap();
            state.readers -= 1;
            if state.readers == 0 {
                drop(state);
                self.cvar.notify_all();
            }
        }

        fn lock_exclusive(&self) {
            let mut state = self.state.lock().unwrap();
            loop {
                if !state.writing && state.readers == 0 {
                    state.writing = true;
                    return;
                }
                state = self.cvar.wait(state).unwrap();
            }
        }

        fn try_lock_exclusive(&self) -> bool {
            let mut state = self.state.lock().unwrap();
            if !state.writing && state.readers == 0 {
                state.writing = true;
                true
            } else {
                false
            }
        }

        unsafe fn unlock_exclusive(&self) {
            let mut state = self.state.lock().unwrap();
            state.writing = false;
            drop(state);
            self.cvar.notify_all();
        }
    }

    // SAFETY: the lock is entirely based on std::sync primitives which are Send+Sync.
    unsafe impl Send for StdRawRwLock {}
    unsafe impl Sync for StdRawRwLock {}
}

/// like `RefCell<T>`
pub type RefCounted<T> = lock_api::RwLock<LockImpl, T>;

/// like `Rc<RefCell<T>>`
pub type RefShared<T> = Arc<RefCounted<T>>;

/// like `Rc<RefCell<T>> + RefMut<T>`
pub type RefGuard<T> = lock_api::ArcRwLockWriteGuard<LockImpl, T>;

pub fn new_shared_ref<T>(inner: T) -> RefShared<T> {
    Arc::new(RefCounted::new(inner))
}

pub fn new_counted_ref<T>(inner: T) -> RefCounted<T> {
    RefCounted::new(inner)
}
