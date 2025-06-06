mod dynamic_params;
mod fd_list;
mod flags;
mod integers;
mod net;
mod newtypes;
mod option;
mod strings;
mod time;

pub struct SerializedField<T>(pub T);
pub use strings::StrOrBytes;
