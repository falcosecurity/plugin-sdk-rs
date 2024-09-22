#![doc = include_str!("../README.md")]
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

fn ident_to_cstr(ident: &Ident) -> syn::LitCStr {
    let mut name = ident.to_string();
    name.push('\0');
    syn::LitCStr::new(
        std::ffi::CStr::from_bytes_with_nul(name.as_bytes()).unwrap(),
        ident.span(),
    )
}

fn ident_to_bstr(ident: &Ident) -> syn::LitByteStr {
    let mut name = ident.to_string();
    name.push('\0');
    syn::LitByteStr::new(name.as_bytes(), ident.span())
}

#[proc_macro_derive(Entry)]
pub fn derive_entry(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let syn::Data::Struct(data) = input.data else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `Entry`",
            )
            .to_compile_error(),
        );
    };

    let name = &input.ident;
    let syn::Fields::Named(fields) = data.fields else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `Entry`",
            )
            .to_compile_error(),
        );
    };

    let fields = fields.named;

    let static_fields = fields.iter().enumerate().map(|(i, f)| {
        let field_name = f.ident.as_ref().unwrap();
        let field_name_bstr = ident_to_bstr(field_name);
        let tag = format!("{}.{}\0", input.ident, field_name);
        let field_tag = syn::LitCStr::new(
            std::ffi::CStr::from_bytes_with_nul(tag.as_bytes()).unwrap(),
            field_name.span(),
        );

        let ty = &f.ty;
        quote!( [#i] #field_tag (#field_name_bstr) as #field_name: #ty)
    });

    quote!(::falco_plugin::impl_export_table!(
        for #name
        {
            #(#static_fields)*
        }
    );)
    .into()
}

#[proc_macro_derive(TableMetadata, attributes(entry_type, name, custom))]
pub fn derive_table_metadata(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let syn::Data::Struct(data) = input.data else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `TableMetadata`",
            )
            .to_compile_error(),
        );
    };

    let name = &input.ident;
    let syn::Fields::Named(fields) = data.fields else {
        return TokenStream::from(
            syn::Error::new(
                input.ident.span(),
                "Only structs with named fields can derive `TableMetadata`",
            )
            .to_compile_error(),
        );
    };

    let fields = fields.named;

    let metadata_macro_args = fields.iter().filter_map(|f| {
        let field = f.ident.as_ref()?;
        let field_name = f
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("name"))
            .filter_map(|a| a.parse_args::<syn::LitCStr>().ok())
            .next()
            .unwrap_or_else(|| ident_to_cstr(field));

        let is_custom = f.attrs.iter().any(|f| f.path().is_ident("custom"));

        if is_custom {
            Some(quote!(add_field(#field, #field_name)))
        } else {
            Some(quote!(get_field(#field, #field_name)))
        }
    });

    let impl_table_metadata = quote!(falco_plugin::impl_import_table_metadata!(
        for #name => {
            #(#metadata_macro_args;)*
        }
    ););

    let entry_type = input
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("entry_type"))
        .filter_map(|a| a.parse_args::<Ident>().ok())
        .next();

    let mut field_traits = Vec::new();
    let mut field_trait_impls = vec![impl_table_metadata];

    let private_ns = Ident::new(&format!("__falco_plugin_private_{}", name), name.span());
    if let Some(entry_type) = entry_type {
        for f in fields {
            let Some(field_name) = f.ident.as_ref() else {
                continue;
            };
            let ty = &f.ty;

            let getter_name = Ident::new(&format!("get_{}", field_name), field_name.span());
            let table_getter_name =
                Ident::new(&format!("get_{}_by_key", field_name), field_name.span());
            let setter_name = Ident::new(&format!("set_{}", field_name), field_name.span());

            field_traits.push(quote!(
                ::falco_plugin::impl_import_table_accessor_traits!(
                    #field_name: #getter_name, #table_getter_name, #setter_name
                );
            ));
            field_trait_impls.push(quote!(
                ::falco_plugin::impl_import_table_accessor_impls!(
                    use #private_ns::#field_name;
                    #field_name(#ty) for #entry_type; meta #name =>
                        #getter_name, #table_getter_name, #setter_name
                );
            ));
        }
    }

    quote!(
        #[allow(non_snake_case)]
        mod #private_ns {
            #(#field_traits)*
        }

        #(#field_trait_impls)*

        #[allow(unused_imports)]
        use #private_ns::*;
    )
    .into()
}
