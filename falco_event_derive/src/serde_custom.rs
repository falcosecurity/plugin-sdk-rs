use proc_macro2::{Ident, TokenStream};
use quote::quote;

pub fn serde_with_tag(ty: &Ident) -> Option<TokenStream> {
    match ty.to_string().as_str() {
        "PT_BYTEBUF" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::bytebuf"))] },
        ),
        "PT_CHARBUF" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr"))] },
        ),
        "PT_CHARBUFARRAY" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr_array"))] },
        ),
        "PT_CHARBUF_PAIR_ARRAY" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr_pair_array"))] },
        ),
        _ => None,
    }
}

pub fn serde_with_option_tag(ty: &Ident) -> Option<TokenStream> {
    match ty.to_string().as_str() {
        "PT_BYTEBUF" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::bytebuf_option"))] },
        ),
        "PT_CHARBUF" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr_option"))] },
        ),
        "PT_CHARBUFARRAY" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr_array_option"))] },
        ),
        "PT_CHARBUF_PAIR_ARRAY" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr_pair_array_option"))] },
        ),
        _ => None,
    }
}

pub fn serde_with_option_tag_owned(ty: &Ident) -> Option<TokenStream> {
    match ty.to_string().as_str() {
        "PT_BYTEBUF" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::bytebuf_option_owned"))] },
        ),
        "PT_CHARBUF" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr_option_owned"))] },
        ),
        "PT_CHARBUFARRAY" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr_array_option_owned"))] },
        ),
        "PT_CHARBUF_PAIR_ARRAY" => Some(
            quote! { #[cfg_attr(feature = "serde", serde(with = "crate::event_derive::serde::cstr_pair_array_option_owned"))] },
        ),
        _ => None,
    }
}
