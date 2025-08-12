use crate::helpers::get_crate_path;
use attribute_derive::FromAttr;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Fields};

#[derive(FromAttr)]
#[from_attr(ident = event_payload)]
struct EventPayloadAttrs {
    length_type: syn::Type,
    code: syn::Expr,
}

pub fn derive_to_bytes(input: TokenStream) -> TokenStream {
    // Parse it as a proc macro
    let input = parse_macro_input!(input as DeriveInput);
    let attrs = match EventPayloadAttrs::from_attributes(&input.attrs) {
        Ok(attrs) => attrs,
        Err(err) => return err.to_compile_error().into(),
    };

    let crate_path = match get_crate_path(&input.attrs) {
        Ok(path) => path,
        Err(e) => return e.into(),
    };

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    if let syn::Data::Struct(ref data) = input.data {
        if let Fields::Named(ref fields) = data.fields {
            let length_type = attrs.length_type;
            let event_code = attrs.code;

            let field_sizes = fields.named.iter().map(|field| {
                let name = &field.ident;
                quote!(#length_type::try_from(self.#name.binary_size()).unwrap())
            });

            let field_sizes_usize = fields.named.iter().map(|field| {
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
            impl #impl_generics #crate_path::events::PayloadToBytes for #name #ty_generics #where_clause {
                #[inline]
                fn binary_size(&self) -> usize {
                    use crate::events::EventPayload;
                    use crate::fields::ToBytes;

                    let mut size = 26;
                    size += ::std::mem::size_of::<#length_type>() * #num_fields;
                    #(size += #field_sizes_usize;)*
                    size
                }

                fn write<W: std::io::Write>(&self, metadata: &crate::events::EventMetadata, mut writer: W) -> std::io::Result<()> {
                    use #crate_path::events::EventPayload;
                    use #crate_path::fields::ToBytes;

                    const NUM_FIELDS: usize = #num_fields;
                    let lengths: [#length_type; NUM_FIELDS] =
                        [#(#field_sizes),*];

                    metadata.write_header_with_lengths(#event_code, lengths, &mut writer)?;
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
    let attrs = match EventPayloadAttrs::from_attributes(&input.attrs) {
        Ok(attrs) => attrs,
        Err(err) => return err.to_compile_error().into(),
    };

    let crate_path = match get_crate_path(&input.attrs) {
        Ok(path) => path,
        Err(e) => return e.into(),
    };

    let (_, ty_generics, where_clause) = input.generics.split_for_impl();

    if let syn::Data::Struct(ref data) = input.data {
        if let Fields::Named(ref fields) = data.fields {
            let length_type = attrs.length_type;
            let event_code = attrs.code;

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
                fn parse(raw: &#crate_path::events::RawEvent<'a>) -> Result<Self, #crate_path::events::PayloadFromBytesError> {
                    use #crate_path::events::PayloadFromBytesError;
                    use #crate_path::events::RawEvent;
                    use #crate_path::fields::FromBytes;
                    use #crate_path::fields::FromBytesError;

                    if raw.event_type != #event_code {
                        return Err(PayloadFromBytesError::TypeMismatch);
                    }

                    let mut params = raw.params::<#length_type>()?;

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
