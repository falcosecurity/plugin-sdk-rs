use proc_macro::TokenStream;

use quote::quote;
use syn::{parse_macro_input, DeriveInput, Fields};

pub fn derive_to_bytes(input: TokenStream) -> TokenStream {
    // Parse it as a proc macro
    let input = parse_macro_input!(input as DeriveInput);

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    if let syn::Data::Struct(ref data) = input.data {
        if let Fields::Named(ref fields) = data.fields {
            let field_sizes = fields.named.iter().map(|field| {
                let name = &field.ident;
                quote!(<Self as EventPayload>::LengthType::try_from(self.#name.binary_size()).unwrap())
            });

            let field_writes = fields.named.iter().map(|field| {
                let name = &field.ident;
                quote!(self.#name.write(&mut writer)?;)
            });

            let name = input.ident;
            let num_fields = fields.named.len();

            return TokenStream::from(quote!(
            impl #impl_generics crate::events::PayloadToBytes for #name #ty_generics #where_clause {
                fn write<W: std::io::Write>(&self, metadata: &crate::events::EventMetadata, mut writer: W) -> std::io::Result<()> {
                    use crate::events::EventPayload;
                    use crate::fields::ToBytes;

                    const NUM_FIELDS: usize = #num_fields;
                    let lengths: [<Self as EventPayload>::LengthType; NUM_FIELDS] =
                        [#(#field_sizes),*];

                    metadata.write_header_with_lengths(Self::ID as u16, lengths, &mut writer)?;
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
                        if !buf.is_empty() {
                            return Err(PayloadFromBytesError::NamedField(#name_str, FromBytesError::LeftoverData));
                        }
                    }
                )
            });

            let field_names = fields.named.iter().map(|field| {
                let name = &field.ident;
                quote!(#name)
            });

            let name = input.ident;

            return TokenStream::from(quote!(
            impl<'a> crate::events::FromRawEvent<'a> for #name #ty_generics #where_clause {
                fn parse(raw: &crate::events::RawEvent<'a>) -> Result<Self, crate::events::PayloadFromBytesError> {
                    use crate::events::EventPayload;
                    use crate::events::PayloadFromBytesError;
                    use crate::events::RawEvent;
                    use crate::fields::FromBytes;
                    use crate::fields::FromBytesError;

                    if raw.event_type != Self::ID as u16 {
                        return Err(PayloadFromBytesError::TypeMismatch);
                    }

                    let mut params = raw.params::<<Self as EventPayload>::LengthType>()?;

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
