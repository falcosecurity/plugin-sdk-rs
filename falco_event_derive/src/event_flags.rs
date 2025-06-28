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

    let enum_debug = filtered.clone().map(|(variant, _)| {
        let variant_str = variant.to_string();
        quote!(Self::#variant => write!(f, "({})", #variant_str))
    });

    quote!(
        #[repr(#repr_type)]
        #[allow(non_camel_case_types)]
        #[non_exhaustive]
        #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[cfg_attr(all(not(docsrs), feature = "derive_deftly"), derive(derive_deftly::Deftly))]
        #[cfg_attr(all(not(docsrs), feature = "derive_deftly"), derive_deftly_adhoc(export))]
        pub enum #name {
            #(#tags,)*
            Unknown(usize),
        }

        impl #name {
            pub fn new(val: #repr_type) -> Self {
                Self::from(val)
            }

            pub fn as_repr(self) -> #repr_type {
                #repr_type::from(self)
            }
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

        impl crate::fields::ToBytes for #name {
            fn binary_size(&self) -> usize {
                std::mem::size_of::<#repr_type>()
            }

            fn write<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
                let repr: #repr_type = (*self).into();
                repr.write(writer)
            }

            fn default_repr() -> impl crate::fields::ToBytes {
                0 as #repr_type
            }
        }

        impl crate::fields::FromBytes<'_> for #name {
            #[inline]
            fn from_bytes(buf: &mut &[u8]) -> Result<Self, crate::fields::FromBytesError>
            where
                Self: Sized,
            {
                let repr = #repr_type::from_bytes(buf)?;
                Ok(repr.into())
            }
        }

        impl ::std::fmt::Debug for #name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                let raw: #repr_type = (*self).into();
                ::std::fmt::Debug::fmt(&raw, f)?;
                match self {
                    #(#enum_debug,)*
                    Self::Unknown(_) => Ok(()),
                }
            }
        }

        impl ::std::fmt::LowerHex for #name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                let raw: #repr_type = (*self).into();
                ::std::fmt::LowerHex::fmt(&raw, f)?;
                match self {
                    Self::Unknown(_) => Ok(()),
                    _ => write!(f, "({:?})", self)
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

    quote!(
        bitflags::bitflags! {
            #[allow(non_camel_case_types)]
            #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
            #[cfg_attr(all(not(docsrs), feature = "derive_deftly"), derive(derive_deftly::Deftly))]
            #[cfg_attr(all(not(docsrs), feature = "derive_deftly"), derive_deftly_adhoc(export))]
            pub struct #name: #repr_type {
                #(#items;)*
                const _ = !0;
            }
        }

        impl crate::fields::ToBytes for #name {
            fn binary_size(&self) -> usize {
                std::mem::size_of::<#repr_type>()
            }

            fn write<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
                (self.bits() as #repr_type).write(writer)
            }

            fn default_repr() -> impl crate::fields::ToBytes {
                0 as #repr_type
            }
        }

        impl crate::fields::FromBytes<'_> for #name {
            #[inline]
            fn from_bytes(buf: &mut &[u8]) -> Result<Self, crate::fields::FromBytesError>
            where
                Self: Sized,
            {
                let repr = #repr_type::from_bytes(buf)?;
                let val = Self::from_bits_retain(repr);
                Ok(val)
            }
        }

        impl ::std::fmt::Debug for #name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{:#x}", self.bits())?;
                let mut first = true;

                let mut it = self.iter_names();
                for (name, bits) in &mut it {
                    if first {
                        f.write_str("(")?;
                        first = false;
                    } else {
                        f.write_str("|")?;
                    }
                    write!(f, "{name}")?;
                }

                let rem = it.remaining().bits();
                if rem != 0 {
                    if first {
                        f.write_str("(")?;
                        first = false;
                    } else {
                        f.write_str("|")?;
                    }
                    write!(f, "{rem:#x}")?;
                }

                if !first {
                    f.write_str(")")?;
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
    let final_name = Ident::new(&format!("{underlying_type}_{name}"), name.span());

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
        _ => panic!("unsupported type {underlying_type}"),
    }
}

fn render_derive_deftly(
    flag_entries: &Punctuated<FlagsEntry, Token![;]>,
) -> proc_macro2::TokenStream {
    let derive_deftly_for_enums = flag_entries.iter().filter_map(|entry| {
        if let FlagsEntry::TypeDecl {
            name,
            underlying_type,
            ..
        } = entry
        {
            match underlying_type.to_string().as_str() {
                "PT_ENUMFLAGS32" | "PT_ENUMFLAGS16" | "PT_ENUMFLAGS8" => {
                    let final_name = Ident::new(&format!("{underlying_type}_{name}"), name.span());
                    Some(quote!(
                        $crate::derive_deftly::derive_deftly_adhoc! {
                            $crate::#final_name: $($body)*
                        }
                    ))
                }
                _ => None,
            }
        } else {
            None
        }
    });

    let derive_deftly_for_bitflags = flag_entries.iter().filter_map(|entry| {
        if let FlagsEntry::TypeDecl {
            name,
            underlying_type,
            ..
        } = entry
        {
            match underlying_type.to_string().as_str() {
                "PT_FLAGS32" | "PT_FLAGS16" | "PT_FLAGS8" | "PT_MODE" => {
                    let final_name = Ident::new(&format!("{underlying_type}_{name}"), name.span());
                    Some(quote!(
                        $crate::derive_deftly::derive_deftly_adhoc! {
                            $crate::#final_name: $($body)*
                        }
                    ))
                }
                _ => None,
            }
        } else {
            None
        }
    });

    quote!(
        #[macro_export]
        /// Derive new features for enum types (`PT_ENUMFLAGS*`)
        ///
        /// This is mostly undocumented on purpose (the details can change without notice),
        /// but feel free to check the `falco_event_serde` crate for example usage.
        macro_rules! derive_deftly_for_enums {
            ($($body:tt)*) => {
                #(#derive_deftly_for_enums)*
            }
        }

        #[macro_export]
        /// Derive new features for bit flag types (`PT_FLAGS*`)
        ///
        /// This is mostly undocumented on purpose (the details can change without notice),
        /// but feel free to check the `falco_event_serde` crate for example usage.
        macro_rules! derive_deftly_for_bitflags {
            ($($body:tt)*) => {
                #(#derive_deftly_for_bitflags)*
            }
        }
    )
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

    let derive_deftly = render_derive_deftly(&flags.flags);

    quote!(
        #(#tokens)*
        #derive_deftly
    )
    .into()
}
