use proc_macro::TokenStream;

mod binary_payload;
mod dynamic_params;
mod event_flags;
mod event_info;
mod format;

#[proc_macro_derive(ToBytes)]
pub fn derive_to_bytes(input: TokenStream) -> TokenStream {
    binary_payload::derive_to_bytes(input)
}

#[proc_macro_derive(FromBytes)]
pub fn derive_from_bytes(input: TokenStream) -> TokenStream {
    binary_payload::derive_from_bytes(input)
}

#[proc_macro]
pub fn event_info(input: TokenStream) -> TokenStream {
    event_info::event_info(input)
}

#[proc_macro]
pub fn event_flags(input: TokenStream) -> TokenStream {
    event_flags::event_flags(input)
}

#[proc_macro]
pub fn dynamic_params(input: TokenStream) -> TokenStream {
    dynamic_params::dynamic_params(input)
}
