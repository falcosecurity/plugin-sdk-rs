use crate::event_info::{lifetime_type, LifetimeType};
use crate::format::formatter_for;
#[cfg(feature = "serde")]
use crate::serde_custom::serde_with_tag;
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::{Brace, Bracket};
use syn::{braced, bracketed, parse_macro_input, LitInt, Token};

#[cfg(not(feature = "serde"))]
fn serde_with_tag(_ty: &Ident) -> Option<proc_macro2::TokenStream> {
    None
}

struct DynamicParamVariant {
    _brackets: syn::token::Bracket,
    discriminant: Ident,
    _eq: Token![=],
    _braces1: syn::token::Brace,
    _braces2: syn::token::Brace,
    _zero1: LitInt,
    _comma1: Token![,],
    field_type: Ident,
    _comma2: Token![,],
    field_format: Ident,
    _comma3: Token![,],
    _zero2: LitInt,
    _comma4: Token![,],
    _zero3: LitInt,
}

impl Parse for DynamicParamVariant {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        let disc;
        let inner;
        Ok(DynamicParamVariant {
            _brackets: bracketed!(disc in input),
            discriminant: disc.parse()?,
            _eq: input.parse()?,
            _braces1: braced!(content in input),
            _braces2: braced!(inner in content),
            _zero1: inner.parse()?,
            _comma1: content.parse()?,
            field_type: content.parse()?,
            _comma2: content.parse()?,
            field_format: content.parse()?,
            _comma3: content.parse()?,
            _zero2: content.parse()?,
            _comma4: content.parse()?,
            _zero3: content.parse()?,
        })
    }
}

impl DynamicParamVariant {
    fn unpack(
        &self,
    ) -> (
        &Ident,
        &Ident,
        Option<proc_macro2::TokenStream>,
        Option<proc_macro2::TokenStream>,
    ) {
        let disc = &self.discriminant;
        let ty = &self.field_type;
        let (field_ref, field_lifetime) = match lifetime_type(&self.field_type.to_string()) {
            LifetimeType::Ref => (Some(quote!(&'a)), None),
            LifetimeType::Generic => (None, Some(quote!(<'a>))),
            LifetimeType::None => (None, None),
        };

        (disc, ty, field_ref, field_lifetime)
    }

    fn variant_definition(&self) -> proc_macro2::TokenStream {
        let (disc, ty, field_ref, field_lifetime) = self.unpack();
        let serde_tag = serde_with_tag(ty);

        quote!(#disc(#serde_tag #field_ref crate::event_derive::event_field_type::#ty #field_lifetime))
    }

    fn owned_variant_definition(&self) -> proc_macro2::TokenStream {
        let (disc, ty, _, _) = self.unpack();
        let serde_tag = serde_with_tag(ty);

        quote!(#disc(
            #serde_tag
            crate::event_derive::event_field_type::owned::#ty
        ))
    }

    fn variant_read(&self) -> proc_macro2::TokenStream {
        let (disc, ty, field_ref, field_lifetime) = self.unpack();

        quote!(crate::ffi:: #disc => {
            Ok(Self:: #disc(
                <#field_ref crate::event_derive::event_field_type::#ty #field_lifetime as crate::event_derive::FromBytes>::from_bytes(buf)?
            ))
        })
    }

    fn variant_binary_size(&self) -> proc_macro2::TokenStream {
        let disc = &self.discriminant;

        quote!(Self:: #disc (val) => 1 + val.binary_size())
    }

    fn variant_write(&self) -> proc_macro2::TokenStream {
        let disc = &self.discriminant;

        quote!(Self:: #disc(val) => {
            writer.write_u8(crate::ffi::#disc as u8)?;
            crate::event_derive::ToBytes::write(val, writer)
        })
    }

    fn variant_fmt(&self) -> proc_macro2::TokenStream {
        let (disc, _, _, _) = self.unpack();
        let mut disc_str = disc.to_string();
        if let Some(idx_pos) = disc_str.find("_IDX_") {
            let substr = &disc_str.as_str()[idx_pos + 5..];
            disc_str = String::from(substr);
        }

        let format_val =
            formatter_for(&self.field_type, &self.field_format, quote!(val), quote!(f));

        quote!(Self:: #disc(val) => {
            f.write_str(#disc_str)?;
            f.write_char(':')?;
            #format_val
        })
    }

    fn variant_borrow(&self) -> proc_macro2::TokenStream {
        let disc = &self.discriminant;

        quote!(Self::#disc(val) => #disc(val.borrow_deref()),)
    }
}

struct DynamicParam {
    _const: Token![const],
    _struct: Token![struct],
    _type: Ident,
    name: Ident,
    _brackets: Bracket,
    _in_brackets: Ident,
    _eq: Token![=],
    _braces: Brace,
    items: Punctuated<DynamicParamVariant, Token![,]>,
}

impl Parse for DynamicParam {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let max;
        let items;
        Ok(DynamicParam {
            _const: input.parse()?,
            _struct: input.parse()?,
            _type: input.parse()?,
            name: input.parse()?,
            _brackets: bracketed!(max in input),
            _in_brackets: max.parse()?,
            _eq: input.parse()?,
            _braces: braced!(items in input),
            items: Punctuated::parse_terminated(&items)?,
        })
    }
}

impl DynamicParam {
    fn borrowed(&self) -> proc_macro2::TokenStream {
        let name = Ident::new(&format!("PT_DYN_{}", self.name), self.name.span());
        let variant_definitions = self.items.iter().map(|v| v.variant_definition());
        let variant_reads = self.items.iter().map(|v| v.variant_read());
        let variant_binary_size = self.items.iter().map(|v| v.variant_binary_size());
        let variant_write = self.items.iter().map(|v| v.variant_write());
        let variant_fmts = self.items.iter().map(|v| v.variant_fmt());

        let wants_lifetime = !self.items.iter().all(|arg| {
            matches!(
                lifetime_type(&arg.field_type.to_string()),
                LifetimeType::None
            )
        });
        let lifetime = if wants_lifetime {
            Some(quote!(<'a>))
        } else {
            None
        };

        #[cfg(feature = "serde")]
        let derives = if wants_lifetime {
            quote!(#[derive(serde::Serialize)])
        } else {
            quote!(
                #[derive(Clone)]
                #[derive(serde::Deserialize)]
                #[derive(serde::Serialize)]
            )
        };

        #[cfg(not(feature = "serde"))]
        let derives = if wants_lifetime {
            None
        } else {
            Some(quote!(#[derive(Clone)]))
        };

        quote!(
            #[allow(non_camel_case_types)]
            #derives
            pub enum #name #lifetime {
                #(#variant_definitions,)*
            }

            impl #lifetime crate::event_derive::ToBytes for #name #lifetime {
                fn binary_size(&self) -> usize {
                    use crate::event_derive::ToBytes;
                    match self {
                        #(#variant_binary_size,)*
                    }
                }
                fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
                    use crate::event_derive::WriteBytesExt;

                    match self {
                        #(#variant_write)*
                    }
                }

                fn default_repr() -> impl crate::event_derive::ToBytes { crate::event_derive::NoDefault }
            }

            impl<'a> crate::event_derive::FromBytes<'a> for #name #lifetime {
                fn from_bytes(buf: &mut &'a [u8]) -> crate::event_derive::FromBytesResult<Self> {
                    use crate::event_derive::ReadBytesExt;
                    let variant = buf.read_u8()?;
                    match variant as u32 {
                        #(#variant_reads,)*
                        _ => Err(crate::event_derive::FromBytesError::InvalidDynDiscriminant),
                    }
                }
            }

            impl #lifetime ::std::fmt::Debug for #name #lifetime {
                fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    use ::std::fmt::Write;

                    match self {
                        #(#variant_fmts)*
                    }
                }
            }

            impl #lifetime ::std::fmt::LowerHex for #name #lifetime {
                fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    ::std::fmt::Debug::fmt(self, f)
                }
            }
        )
    }

    fn owned(&self) -> proc_macro2::TokenStream {
        let name = Ident::new(&format!("PT_DYN_{}", self.name), self.name.span());
        let variant_definitions = self.items.iter().map(|v| v.owned_variant_definition());
        let variant_borrows = self.items.iter().map(|v| v.variant_borrow());

        let wants_lifetime = !self.items.iter().all(|arg| {
            matches!(
                lifetime_type(&arg.field_type.to_string()),
                LifetimeType::None
            )
        });

        #[cfg(feature = "serde")]
        let serde_derives = quote!(
            #[derive(serde::Deserialize)]
            #[derive(serde::Serialize)]
        );

        #[cfg(not(feature = "serde"))]
        let serde_derives = quote!();

        if wants_lifetime {
            quote!(
                #[allow(non_camel_case_types)]
                #serde_derives
                pub enum #name {
                    #(#variant_definitions,)*
                }

                impl crate::event_derive::Borrow for #name {
                    type Borrowed<'a> = super::#name<'a>;

                    fn borrow(&self) -> Self::Borrowed<'_> {
                        use crate::event_derive::BorrowDeref;
                        use super::#name::*;

                        match self {
                            #(#variant_borrows)*
                        }
                    }
                }

                impl ::std::fmt::Debug for #name {
                    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                        use crate::event_derive::Borrow;
                        ::std::fmt::Debug::fmt(&self.borrow(), f)
                    }
                }

                impl ::std::fmt::LowerHex for #name {
                    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                        use crate::event_derive::Borrow;
                        ::std::fmt::LowerHex::fmt(&self.borrow(), f)
                    }
                }
            )
        } else {
            quote!(pub use super::#name;)
        }
    }
}

struct DynamicParams {
    params: Punctuated<DynamicParam, Token![;]>,
}

impl Parse for DynamicParams {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(DynamicParams {
            params: Punctuated::parse_terminated(input)?,
        })
    }
}

pub fn dynamic_params(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DynamicParams);

    let borrowed = input.params.iter().map(|param| param.borrowed());
    let owned = input.params.iter().map(|param| param.owned());
    quote!(
        #(#borrowed)*

        pub mod owned {
            #(#owned)*
        }
    )
    .into()
}
