use proc_macro::TokenStream;
use quote::quote;
use std::collections::{BTreeMap, BTreeSet};
use syn::parse::{Nothing, Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::{Brace, Bracket};
use syn::{braced, bracketed, parse_macro_input, Ident, LitInt, LitStr, Token};

enum NumberOr<T: Parse> {
    Number,
    Token(T),
}

impl<T: Parse> Parse for NumberOr<T> {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(LitInt) {
            let _: LitInt = input.parse()?;
            Ok(Self::Number)
        } else {
            Ok(Self::Token(input.parse()?))
        }
    }
}

struct FlagItem {
    _braces: Brace,
    name: NumberOr<LitStr>,
    _comma: Token![,],
    value: NumberOr<Ident>,
}

impl Parse for FlagItem {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let item;
        Ok(FlagItem {
            _braces: braced!(item in input),
            name: item.parse()?,
            _comma: item.parse()?,
            value: item.parse()?,
        })
    }
}

type Skips = Option<(Token![!], Punctuated<Ident, Token![,]>)>;

enum FlagsEntry {
    TypeDecl {
        _type: Token![type],
        name: Ident,
        _colon: Token![:],
        underlying_type: Ident,
        skips: Skips,
    },
    FlagDecl {
        _const: Token![const],
        _struct: Token![struct],
        _type: Ident,
        name: Ident,
        _brackets: Bracket,
        _in_brackets: Nothing,
        _eq: Token![=],
        _braces: Brace,
        items: Punctuated<FlagItem, Token![,]>,
    },
}

impl Parse for FlagsEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(Token![type]) {
            Ok(FlagsEntry::TypeDecl {
                _type: input.parse()?,
                name: input.parse()?,
                _colon: input.parse()?,
                underlying_type: input.parse()?,
                skips: if input.peek(Token![!]) {
                    Some((input.parse()?, Punctuated::parse_separated_nonempty(input)?))
                } else {
                    None
                },
            })
        } else {
            let nothing;
            let items;
            Ok(FlagsEntry::FlagDecl {
                _const: input.parse()?,
                _struct: input.parse()?,
                _type: input.parse()?,
                name: input.parse()?,
                _brackets: bracketed!(nothing in input),
                _in_brackets: nothing.parse()?,
                _eq: input.parse()?,
                _braces: braced!(items in input),
                items: Punctuated::parse_terminated(&items)?,
            })
        }
    }
}

struct Flags {
    flags: Punctuated<FlagsEntry, Token![;]>,
}

impl Parse for Flags {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Flags {
            flags: Punctuated::parse_terminated(input)?,
        })
    }
}

fn render_enum(
    name: &Ident,
    repr_type: proc_macro2::TokenStream,
    items: impl Iterator<Item = (Ident, Ident)> + Clone,
    skips: &Skips,
) -> proc_macro2::TokenStream {
    let mut skipped = BTreeSet::new();
    if let Some((_, skips)) = skips {
        for skip in skips {
            skipped.insert(skip.to_string());
        }
    }

    let filtered = items.filter(|(_, value)| !skipped.contains(&value.to_string()));

    let tags = filtered.clone().map(|(variant, _)| variant);

    let raw_to_enum = filtered
        .clone()
        .map(|(variant, value)| quote!(crate::ffi::#value => Self::#variant));

    let enum_to_raw = filtered
        .clone()
        .map(|(variant, value)| quote!(#name::#variant => crate::ffi::#value as #repr_type));

    #[cfg(feature = "serde")]
    let serde_derives = quote!(
        #[derive(serde::Deserialize)]
        #[derive(serde::Serialize)]
    );

    #[cfg(not(feature = "serde"))]
    let serde_derives = quote!();

    quote!(
        #[repr(#repr_type)]
        #[allow(non_camel_case_types)]
        #[non_exhaustive]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #serde_derives
        pub enum #name {
            #(#tags,)*
            Unknown(usize),
        }

        impl From<#repr_type> for #name {
            fn from(val: #repr_type) -> Self {
                match val as u32 {
                    #(#raw_to_enum,)*
                    other => Self::Unknown(other as usize),
                }
            }
        }

        impl From<#name> for #repr_type {
            fn from(val: #name) -> #repr_type {
                match val {
                    #(#enum_to_raw,)*
                    #name::Unknown(other) => other as #repr_type,
                }
            }
        }

        impl crate::event_derive::ToBytes for #name {
            fn binary_size(&self) -> usize {
                std::mem::size_of::<#repr_type>()
            }

            fn write<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
                let repr: #repr_type = (*self).into();
                repr.write(writer)
            }

            fn default_repr() -> impl crate::event_derive::ToBytes {
                0 as #repr_type
            }
        }

        impl crate::event_derive::FromBytes<'_> for #name {
            fn from_bytes(buf: &mut &[u8]) -> crate::event_derive::FromBytesResult<Self>
            where
                Self: Sized,
            {
                let repr = #repr_type::from_bytes(buf)?;
                Ok(repr.into())
            }
        }

        impl crate::event_derive::Borrowed for #name {
            type Owned = Self;
        }

        impl<F> crate::event_derive::Format<F> for #name
        where
            #repr_type: crate::event_derive::Format<F>,
        {
            fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                let raw: #repr_type = (*self).into();
                raw.format(fmt)?;
                match self {
                    Self::Unknown(_) => Ok(()),
                    _ => write!(fmt, "({:?})", self)
                }
            }
        }
    )
}

fn render_bitflags(
    name: &Ident,
    repr_type: proc_macro2::TokenStream,
    items: impl Iterator<Item = (Ident, Ident)>,
) -> proc_macro2::TokenStream {
    let items = items.map(|(name, value)| quote!(const #name = crate::ffi::#value as #repr_type));

    #[cfg(feature = "serde")]
    let serde_derives = quote!(
        #[derive(serde::Deserialize)]
        #[derive(serde::Serialize)]
    );

    #[cfg(not(feature = "serde"))]
    let serde_derives = quote!();

    quote!(
        bitflags::bitflags! {
            #[allow(non_camel_case_types)]
            #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
            #serde_derives
            pub struct #name: #repr_type {
                #(#items;)*
                const _ = !0;
            }
        }

        impl crate::event_derive::ToBytes for #name {
            fn binary_size(&self) -> usize {
                std::mem::size_of::<#repr_type>()
            }

            fn write<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
                (self.bits() as #repr_type).write(writer)
            }

            fn default_repr() -> impl crate::event_derive::ToBytes {
                0 as #repr_type
            }
        }

        impl crate::event_derive::FromBytes<'_> for #name {
            fn from_bytes(buf: &mut &[u8]) -> crate::event_derive::FromBytesResult<Self>
            where
                Self: Sized,
            {
                let repr = #repr_type::from_bytes(buf)?;
                let val = Self::from_bits_retain(repr);
                Ok(val)
            }
        }

        impl crate::event_derive::Borrowed for #name {
            type Owned = Self;
        }

        impl<F> crate::event_derive::Format<F> for #name {
            fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(fmt, "{:#x}", self.bits())?;
                let mut first = true;

                let mut it = self.iter_names();
                for (name, bits) in &mut it {
                    if first {
                        fmt.write_str("(")?;
                        first = false;
                    } else {
                        fmt.write_str("|")?;
                    }
                    write!(fmt, "{name}")?;
                }

                let rem = it.remaining().bits();
                if rem != 0 {
                    if first {
                        fmt.write_str("(")?;
                        first = false;
                    } else {
                        fmt.write_str("|")?;
                    }
                    write!(fmt, "{rem:#x}")?;
                }

                if !first {
                    fmt.write_str(")")?;
                }

                Ok(())
            }
        }
    )
}

fn render_flags_type(
    name: &Ident,
    underlying_type: &Ident,
    items: &Punctuated<FlagItem, Token![,]>,
    skips: &Skips,
) -> proc_macro2::TokenStream {
    let final_name = Ident::new(&format!("{}_{}", underlying_type, name), name.span());

    let items = items.iter().filter_map(|it| {
        let NumberOr::Token(ref name) = it.name else {
            return None;
        };
        let NumberOr::Token(ref value) = it.value else {
            return None;
        };

        let name = Ident::new(&name.value(), name.span());

        Some((name, value.clone()))
    });

    match underlying_type.to_string().as_str() {
        "PT_FLAGS32" | "PT_MODE" => render_bitflags(&final_name, quote!(u32), items),
        "PT_FLAGS16" => render_bitflags(&final_name, quote!(u16), items),
        "PT_FLAGS8" => render_bitflags(&final_name, quote!(u8), items),
        "PT_ENUMFLAGS32" => render_enum(&final_name, quote!(u32), items, skips),
        "PT_ENUMFLAGS16" => render_enum(&final_name, quote!(u16), items, skips),
        "PT_ENUMFLAGS8" => render_enum(&final_name, quote!(u8), items, skips),
        _ => panic!("unsupported type {}", underlying_type),
    }
}

pub fn event_flags(input: TokenStream) -> TokenStream {
    let flags = parse_macro_input!(input as Flags);

    let mut flag_items = BTreeMap::new();
    for item in &flags.flags {
        if let FlagsEntry::FlagDecl { name, items, .. } = &item {
            flag_items.insert(name, items);
        }
    }

    let mut tokens = Vec::new();
    for item in &flags.flags {
        if let FlagsEntry::TypeDecl {
            name,
            underlying_type,
            skips,
            ..
        } = item
        {
            tokens.push(render_flags_type(
                name,
                underlying_type,
                flag_items.get(name).expect("blah"),
                skips,
            ))
        }
    }

    quote!(
        #(#tokens)*
    )
    .into()
}
