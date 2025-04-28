use proc_macro2::Ident;
use quote::quote;

pub fn display_wrapper_for(
    pt_type: &Ident,
    val_tt: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    match pt_type.to_string().as_str() {
        "PT_ABSTIME" => quote!(#val_tt.map(|t| crate::event_derive::SystemTimeFormatter(*t))),
        "PT_BYTEBUF" => quote!(#val_tt.map(|t| crate::format::ByteBufFormatter(t))),
        "PT_CHARBUF" => quote!(#val_tt.map(|t| crate::format::CStrFormatter(t))),
        "PT_CHARBUFARRAY" => {
            quote!(#val_tt.map(|t| crate::format::CStrArrayFormatter(&t)))
        }
        "PT_CHARBUF_PAIR_ARRAY" => {
            quote!(#val_tt.map(|t| crate::format::CStrPairArrayFormatter(&t)))
        }
        "PT_FSPATH" => quote!(#val_tt.map(|p| p.display())),
        _ => val_tt,
    }
}

pub fn formatter_for(
    pt_type: &Ident,
    pf_type: &Ident,
    val_tt: proc_macro2::TokenStream,
    formatter_tt: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    match (pt_type.to_string().as_str(), pf_type.to_string().as_str()) {
        ("PT_FSPATH", _) => quote!(::std::fmt::Display::fmt(#val_tt, #formatter_tt)),
        ("PT_BYTEBUF", "PF_HEX") => quote!(write!(#formatter_tt, "{:x?}", #val_tt)),
        (_, "PF_HEX") => quote!(::std::fmt::LowerHex::fmt(#val_tt, #formatter_tt)),
        (_, "PF_OCT") => quote!(::std::fmt::Octal::fmt(#val_tt, #formatter_tt)),
        _ => quote!(::std::fmt::Debug::fmt(#val_tt, #formatter_tt)),
    }
}
