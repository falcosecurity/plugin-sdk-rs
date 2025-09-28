use std::panic::UnwindSafe;

pub(crate) fn catch_panic<T, F>(f: F) -> Result<T, anyhow::Error>
where
    F: UnwindSafe + FnOnce() -> Result<T, anyhow::Error>,
{
    // Call `f` explicitly so debuggers can step into the closure body
    // before entering std's catch_unwind machinery.
    #[allow(clippy::redundant_closure)]
    std::panic::catch_unwind(move || f()).unwrap_or_else(|e| {
        if let Some(e) = e.downcast_ref::<&'static str>() {
            Err(anyhow::anyhow!("{}", e))
        } else if let Some(e) = e.downcast_ref::<String>() {
            Err(anyhow::anyhow!("{}", e))
        } else {
            Err(anyhow::anyhow!("panic"))
        }
    })
}
