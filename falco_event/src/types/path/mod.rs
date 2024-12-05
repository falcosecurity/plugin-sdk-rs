mod absolute_path;
mod relative_path;

pub use relative_path::*;

#[cfg(feature = "serde")]
pub mod serde {
    pub use super::absolute_path::serde::*;
}
