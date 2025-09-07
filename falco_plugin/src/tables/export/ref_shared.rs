use std::sync::Arc;

#[cfg(feature = "thread-safe-tables")]
use parking_lot::RawRwLock as LockImpl;

#[cfg(not(feature = "thread-safe-tables"))]
use refcell_lock_api::raw::CellRwLock as LockImpl;

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
