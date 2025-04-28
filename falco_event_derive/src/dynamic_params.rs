use crate::event_info::{lifetime_type, LifetimeType};
use crate::format::formatter_for;
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::{Brace, Bracket};
use syn::{braced, bracketed, parse_macro_input, LitInt, Token};

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

    fn variant_type(&self) -> proc_macro2::TokenStream {
        let (_, ty, field_ref, field_lifetime) = self.unpack();

        quote!(#field_ref crate::fields::types::#ty #field_lifetime)
    }

    fn variant_definition(&self) -> proc_macro2::TokenStream {
        let disc = &self.discriminant;

        let ty = self.variant_type();
        quote!(#disc(#ty))
    }

    fn variant_read(&self) -> proc_macro2::TokenStream {
        let disc = &self.discriminant;
        let ty = self.variant_type();

        quote!(crate::ffi:: #disc => {
            Ok(Self:: #disc(
                <#ty as crate::fields::FromBytes>::from_bytes(buf)?
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
            crate::fields::ToBytes::write(val, writer)
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
    fn render(&self) -> proc_macro2::TokenStream {
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

        let lifetime = wants_lifetime.then_some(quote!(<'a>));

        quote!(
            #[allow(non_camel_case_types)]
            #[derive(Clone)]
            #[derive(derive_deftly::Deftly)]
            #[derive_deftly_adhoc(export)]
            pub enum #name #lifetime {
                #(#variant_definitions,)*
            }

            impl #lifetime crate::fields::ToBytes for #name #lifetime {
                fn binary_size(&self) -> usize {
                    use crate::fields::ToBytes;
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

                fn default_repr() -> impl crate::fields::ToBytes { crate::fields::NoDefault }
            }

            impl<'a> crate::fields::FromBytes<'a> for #name #lifetime {
                fn from_bytes(buf: &mut &'a [u8]) -> crate::fields::FromBytesResult<Self> {
                    use crate::event_derive::ReadBytesExt;
                    let variant = buf.read_u8()?;
                    match variant as u32 {
                        #(#variant_reads,)*
                        _ => Err(crate::fields::FromBytesError::InvalidDynDiscriminant),
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
}

fn render_derive_deftly(params: &Punctuated<DynamicParam, Token![;]>) -> proc_macro2::TokenStream {
    let derives = params.iter().map(|param| {
        let name = Ident::new(&format!("PT_DYN_{}", param.name), param.name.span());
        quote!(
            $crate::derive_deftly::derive_deftly_adhoc! {
                $crate::#name: $($body)*
            }
        )
    });

    quote!(
        #[macro_export]
        macro_rules! derive_deftly_for_dynamic_params {
            ($($body:tt)*) => {
                #(#derives)*
            }
        }
    )
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

    let borrowed = input.params.iter().map(|param| param.render());
    let derive_deftly = render_derive_deftly(&input.params);
    quote!(
        #(#borrowed)*

        #derive_deftly
    )
    .into()
}
