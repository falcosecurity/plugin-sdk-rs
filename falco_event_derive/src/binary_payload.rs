use proc_macro::TokenStream;

use quote::quote;
use syn::{parse_macro_input, DeriveInput, Fields};

pub fn derive_to_bytes(input: TokenStream) -> TokenStream {
    // Parse it as a proc macro
    let input = parse_macro_input!(input as DeriveInput);

    let crate_path: syn::Path = syn::parse(quote!(crate::event_derive).into()).unwrap();
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    if let syn::Data::Struct(ref data) = input.data {
        if let Fields::Named(ref fields) = data.fields {
            let field_sizes = fields.named.iter().map(|field| {
                let name = &field.ident;
                quote!(self.#name.binary_size())
            });

            let field_writes = fields.named.iter().map(|field| {
                let name = &field.ident;
                quote!(self.#name.write(&mut writer)?;)
            });

            let name = input.ident;
            let num_fields = fields.named.len();

            return TokenStream::from(quote!(
            impl #impl_generics #crate_path::PayloadToBytes for #name #ty_generics #where_clause {
                fn write<W: std::io::Write>(&self, metadata: &crate::events::EventMetadata, mut writer: W) -> std::io::Result<()> {
                    use #crate_path::*;
                    use crate::events::EventPayload;

                    const NUM_FIELDS: usize = #num_fields;
                    let length_size = if Self::LARGE { 4 } else { 2 };
                    let lengths: [usize; NUM_FIELDS] =
                        [#(#field_sizes),*];
                    let len: usize = 26 + // header
                        (length_size * NUM_FIELDS) +
                        lengths.iter().sum::<usize>();

                    writer.write_u64::<NativeEndian>(metadata.ts)?;
                    writer.write_i64::<NativeEndian>(metadata.tid)?;
                    writer.write_u32::<NativeEndian>(len as u32)?;
                    writer.write_u16::<NativeEndian>(Self::ID as u16)?;
                    writer.write_u32::<NativeEndian>(NUM_FIELDS as u32)?;

                    for param_len in lengths {
                        if Self::LARGE {
                            writer.write_u32::<NativeEndian>(param_len as u32)?;
                        } else {
                            writer.write_u16::<NativeEndian>(param_len as u16)?;
                        }
                    }

                    #(#field_writes)*
                    Ok(())
                }
            }
            ));
        }
    }

    TokenStream::from(
        syn::Error::new(
            input.ident.span(),
            "Only structs with named fields can derive `ToBytes`",
        )
        .to_compile_error(),
    )
}
pub fn derive_from_bytes(input: TokenStream) -> TokenStream {
    // Parse it as a proc macro
    let input = parse_macro_input!(input as DeriveInput);

    let crate_path: syn::Path = syn::parse(quote!(crate::event_derive).into()).unwrap();
    let (_, ty_generics, where_clause) = input.generics.split_for_impl();

    if let syn::Data::Struct(ref data) = input.data {
        if let Fields::Named(ref fields) = data.fields {
            let field_reads = fields.named.iter().map(|field| {
                let name = &field.ident;
                let name_str = name.as_ref().map(|i| i.to_string());
                quote!(
                    let mut maybe_next_field = params.next().transpose()
                        .map_err(|e| PayloadFromBytesError::NamedField(#name_str, e))?;
                    let #name = FromBytes::from_maybe_bytes(maybe_next_field.as_mut())
                        .map_err(|e| PayloadFromBytesError::NamedField(#name_str, e))?;
                    if let Some(buf) = maybe_next_field {
                        debug_assert!(buf.is_empty());
                    }
                )
            });

            let field_names = fields.named.iter().map(|field| {
                let name = &field.ident;
                quote!(#name)
            });

            let name = input.ident;

            return TokenStream::from(quote!(
            impl<'a> #crate_path::PayloadFromBytes<'a> for #name #ty_generics #where_clause {
                fn read(mut params: impl Iterator<Item=#crate_path::FromBytesResult<&'a [u8]>>) -> Result<Self, crate::events::PayloadFromBytesError> {
                    use #crate_path::*;
                    use crate::events::PayloadFromBytesError;
                    #(#field_reads)*

                    Ok(#name {
                        #(#field_names),*
                    })
                }
            }
            ));
        }
    }

    TokenStream::from(
        syn::Error::new(
            input.ident.span(),
            "Only structs with named fields can derive `FromBytes`",
        )
        .to_compile_error(),
    )
}
