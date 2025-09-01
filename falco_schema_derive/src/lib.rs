#![doc = include_str!("../README.md")]

use proc_macro::TokenStream;

mod dynamic_params;
mod event_flags;
mod event_info;
mod format;

#[proc_macro]
#[doc(hidden)]
pub fn event_info(input: TokenStream) -> TokenStream {
    event_info::event_info(input)
}

#[proc_macro]
#[doc(hidden)]
pub fn event_flags(input: TokenStream) -> TokenStream {
    event_flags::event_flags(input)
}

#[proc_macro]
#[doc(hidden)]
pub fn dynamic_params(input: TokenStream) -> TokenStream {
    dynamic_params::dynamic_params(input)
}
