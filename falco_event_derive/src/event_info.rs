use crate::format::{display_wrapper_for, formatter_for};
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{braced, bracketed, parse_macro_input, Token};

pub(crate) enum LifetimeType {
    None,
    Ref,
    Generic,
}

pub(crate) fn lifetime_type(name: &str) -> LifetimeType {
    match name {
        "PT_CHARBUF" | "PT_BYTEBUF" | "PT_FSPATH" => LifetimeType::Ref,
        "PT_FDLIST"
        | "PT_SOCKADDR"
        | "PT_SOCKTUPLE"
        | "PT_FSRELPATH"
        | "PT_CHARBUFARRAY"
        | "PT_CHARBUF_PAIR_ARRAY"
        | "PT_DYN_sockopt_dynamic_param" => LifetimeType::Generic,
        _ => LifetimeType::None,
    }
}

enum IdentOrNumber {
    Ident(Ident),
    Number(syn::LitInt),
}

impl Parse for IdentOrNumber {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(syn::LitInt) {
            Ok(Self::Number(input.parse()?))
        } else {
            Ok(Self::Ident(input.parse()?))
        }
    }
}

type EventArgInfo = Option<(Token![,], IdentOrNumber, Option<(Token![,], Ident)>)>;

struct EventArg {
    _braces: syn::token::Brace,
    name: syn::LitStr,
    _comma1: Token![,],
    field_type: Ident,
    _comma2: Token![,],
    field_format: Ident,
    info: EventArgInfo,
}

impl EventArg {
    fn final_field_type_name(&self) -> Ident {
        if let Some((_, IdentOrNumber::Ident(info), _)) = &self.info {
            Ident::new(
                &format!("{}_{}", self.field_type, info),
                self.field_type.span(),
            )
        } else {
            self.field_type.clone()
        }
    }

    fn ident(&self) -> Ident {
        let mut name = Ident::new(&self.name.value(), self.name.span());
        if syn::parse::<Ident>(quote!(#name).into()).is_err() {
            // #name is a keyword
            name = Ident::new(&format!("{name}_"), name.span());
        }

        name
    }

    fn lifetimes(
        &self,
    ) -> (
        Option<proc_macro2::TokenStream>,
        Option<proc_macro2::TokenStream>,
    ) {
        let field_type = self.final_field_type_name();

        match lifetime_type(&field_type.to_string()) {
            LifetimeType::Ref => (Some(quote!(&'a)), None),
            LifetimeType::Generic => (None, Some(quote!(<'a>))),
            LifetimeType::None => (None, None),
        }
    }

    fn field_type(&self) -> proc_macro2::TokenStream {
        let field_type = self.final_field_type_name();
        let (field_ref, field_lifetime) = self.lifetimes();

        quote!(::std::option::Option<#field_ref crate::fields::types::#field_type #field_lifetime>)
    }

    fn field_definition(&self) -> proc_macro2::TokenStream {
        let name = self.ident();

        let field_type = self.field_type();
        quote!(#[allow(non_snake_case)] pub #name: #field_type)
    }

    fn dirfd_method(&self, event_info: &EventInfo) -> Option<proc_macro2::TokenStream> {
        if let Some((_, IdentOrNumber::Number(num), _)) = &self.info {
            let num = num.base10_parse().ok()?;
            let (_, _, args) = event_info.args.as_ref()?;
            let dirfd_arg = args.iter().nth(num)?.ident();
            let method_name =
                Ident::new(&format!("{}_dirfd", &self.name.value()), self.name.span());

            Some(quote!(
                pub fn #method_name(&self) -> std::option::Option<crate::fields::types::PT_FD> {
                    self.#dirfd_arg
                }
            ))
        } else {
            None
        }
    }
}

impl Parse for EventArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        Ok(EventArg {
            _braces: braced!(content in input),
            name: content.parse()?,
            _comma1: content.parse()?,
            field_type: content.parse()?,
            _comma2: content.parse()?,
            field_format: content.parse()?,
            info: if content.peek(Token![,]) {
                Some((
                    content.parse()?,
                    content.parse()?,
                    if content.peek(Token![,]) {
                        Some((content.parse()?, content.parse()?))
                    } else {
                        None
                    },
                ))
            } else {
                None
            },
        })
    }
}

struct EventInfo {
    _brackets: syn::token::Bracket,
    event_code: Ident,
    _eq: Token![=],
    _braces1: syn::token::Brace,
    name: syn::LitStr,
    _comma1: Token![,],
    _categories: syn::punctuated::Punctuated<Ident, Token![|]>,
    _comma2: Token![,],
    flags: syn::punctuated::Punctuated<Ident, Token![|]>,
    _comma3: Token![,],
    _arg_count: syn::LitInt,
    args: Option<(
        Token![,],
        syn::token::Brace,
        syn::punctuated::Punctuated<EventArg, Token![,]>,
    )>,
}

impl Parse for EventInfo {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident_group;
        let event;
        let args;
        Ok(EventInfo {
            _brackets: bracketed!(ident_group in input),
            event_code: ident_group.parse()?,
            _eq: input.parse()?,
            _braces1: braced!(event in input),
            name: event.parse()?,
            _comma1: event.parse()?,
            _categories: syn::punctuated::Punctuated::parse_separated_nonempty(&event)?,
            _comma2: event.parse()?,
            flags: syn::punctuated::Punctuated::parse_separated_nonempty(&event)?,
            _comma3: event.parse()?,
            _arg_count: event.parse()?,
            args: if event.peek(Token![,]) {
                Some((
                    event.parse()?,
                    braced!(args in event),
                    syn::punctuated::Punctuated::parse_terminated(&args)?,
                ))
            } else {
                None
            },
        })
    }
}

impl EventInfo {
    fn args(&self) -> impl Iterator<Item = &EventArg> {
        self.args
            .as_ref()
            .into_iter()
            .flat_map(|(_, _, args)| args.into_iter())
    }

    fn typedef(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        let event_type = Ident::new(
            &event_code.to_string().replace("PPME_", ""),
            event_code.span(),
        );

        let fields = self.args().map(|arg| arg.field_definition());
        let wants_lifetime = !self.args().all(|arg| {
            matches!(
                lifetime_type(&arg.final_field_type_name().to_string()),
                LifetimeType::None
            )
        });

        let lifetime = wants_lifetime.then_some(quote!(<'a>));
        let field_fmts = self.args().map(|field| {
            let name = &field.name;
            let ident = field.ident();

            let display_wrapper =
                display_wrapper_for(&field.field_type, quote!(self.#ident.as_ref()));
            let display_val = quote!(crate::format::OptionFormatter(#display_wrapper));

            let format_val = formatter_for(
                &field.field_type,
                &field.field_format,
                quote!(&#display_val),
                quote!(f),
            );

            quote!(
                f.write_char(' ')?;
                f.write_str(#name)?;
                f.write_char('=')?;
                #format_val?;
            )
        });
        let dirfd_methods = self.args().map(|a| a.dirfd_method(self));

        let is_large = self.flags.iter().any(|flag| *flag == "EF_LARGE_PAYLOAD");
        let name = &self.name;
        let length_type = match is_large {
            true => quote!(u32),
            false => quote!(u16),
        };

        quote!(
            #[allow(non_camel_case_types)]
            #[derive(Clone, Copy)]
            #[derive(falco_event_derive::FromBytes)]
            #[derive(falco_event_derive::ToBytes)]
            #[cfg_attr(all(not(docsrs), feature = "derive_deftly"), derive(derive_deftly::Deftly))]
            #[cfg_attr(all(not(docsrs), feature = "derive_deftly"), derive_deftly_adhoc(export))]
            pub struct #event_code #lifetime {
                #(#fields,)*
            }

            impl #lifetime #event_code #lifetime {
                #(#dirfd_methods)*
            }

            impl #lifetime crate::events::EventPayload for #event_code #lifetime {
                const ID: EventType = EventType:: #event_type;
                const NAME: &'static str = #name;

                type LengthType = #length_type;
            }

            impl #lifetime ::std::fmt::Debug for #event_code #lifetime {
                fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    use std::fmt::Write;

                    match <Self as crate::events::EventPayload>::direction() {
                        crate::events::EventDirection::Entry => f.write_str("> ")?,
                        crate::events::EventDirection::Exit => f.write_str("< ")?,
                    }
                    f.write_str(#name)?;
                    #(#field_fmts)*
                    Ok(())
                }
            }
        )
    }

    fn derive_deftly(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        quote!(
            $crate::derive_deftly::derive_deftly_adhoc! {
                $crate::#event_code: $($body)*
            }
        )
    }

    fn type_variant(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        let event_type = Ident::new(
            &event_code.to_string().replace("PPME_", ""),
            event_code.span(),
        );
        let raw_ident = Ident::new(
            &format!("ppm_event_code_{}", self.event_code),
            self.event_code.span(),
        );

        quote!(#event_type = crate::ffi::#raw_ident as u16)
    }

    fn enum_variant(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        let event_type = Ident::new(
            &event_code.to_string().replace("PPME_", ""),
            event_code.span(),
        );
        let wants_lifetime = !self.args().all(|arg| {
            matches!(
                lifetime_type(&arg.final_field_type_name().to_string()),
                LifetimeType::None
            )
        });

        let lifetime = if wants_lifetime {
            Some(quote!(<'a>))
        } else {
            None
        };

        quote!(#event_type(#event_code #lifetime))
    }

    fn enum_match(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        let event_type = Ident::new(
            &event_code.to_string().replace("PPME_", ""),
            event_code.span(),
        );
        let raw_ident = Ident::new(
            &format!("ppm_event_code_{}", self.event_code),
            self.event_code.span(),
        );
        quote!(crate::ffi:: #raw_ident => {
            let params = <#event_code>::parse(self)?;
            AnyEvent::#event_type(params)
        })
    }

    fn variant_fmt(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        let event_type = Ident::new(
            &event_code.to_string().replace("PPME_", ""),
            event_code.span(),
        );

        quote!(
            AnyEvent::#event_type(inner) => ::std::fmt::Debug::fmt(&inner, f),
        )
    }

    fn variant_to_bytes(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        let event_type = Ident::new(
            &event_code.to_string().replace("PPME_", ""),
            event_code.span(),
        );

        quote!(
            AnyEvent::#event_type(inner) => {
                inner.write(metadata, writer)
            }
        )
    }

    fn variant_binary_size(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        let event_type = Ident::new(
            &event_code.to_string().replace("PPME_", ""),
            event_code.span(),
        );

        quote!(
            AnyEvent::#event_type(inner) => inner.binary_size(),
        )
    }
}

struct Events {
    events: syn::punctuated::Punctuated<EventInfo, Token![,]>,
}

impl Parse for Events {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Events {
            events: syn::punctuated::Punctuated::parse_terminated(input)?,
        })
    }
}

impl Events {
    fn typedefs(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(move |e| e.typedef())
    }

    fn derive_deftly(&self) -> proc_macro2::TokenStream {
        let derives = self.events.iter().map(|e| e.derive_deftly());
        quote!(
            #[macro_export]
            /// Derive new features for event types
            ///
            /// This is mostly undocumented on purpose (the details can change without notice),
            /// but feel free to check the `falco_event_serde` crate for example usage.
            ///
            /// **Note**: using this macro does not affect the `AnyEvent` type, so you will
            /// possibly need to invoke `derive_deftly_adhoc!` to add new features to `AnyEvent`.
            macro_rules! derive_deftly_for_events {
                ($($body:tt)*) => {
                    #(#derives)*
                }
            }
        )
    }

    fn type_variants(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.type_variant())
    }

    fn enum_variants(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(move |e| e.enum_variant())
    }

    fn enum_matches(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.enum_match())
    }

    fn variant_fmts(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.variant_fmt())
    }

    fn variants_to_bytes(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.variant_to_bytes())
    }

    fn variants_binary_size(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.variant_binary_size())
    }
}

fn event_info_variant(events: &Events) -> proc_macro2::TokenStream {
    let typedefs = events.typedefs();
    let derive_deftly = events.derive_deftly();
    let variants = events.enum_variants();
    let variant_fmts = events.variant_fmts();
    let variants_to_bytes = events.variants_to_bytes();
    let variants_binary_size = events.variants_binary_size();
    let lifetime = quote!(<'a>);

    quote!(
        #(#typedefs)*
        #derive_deftly

        #[allow(non_camel_case_types)]
        #[cfg_attr(all(not(docsrs), feature = "derive_deftly"), derive(derive_deftly::Deftly))]
        #[cfg_attr(all(not(docsrs), feature = "derive_deftly"), derive_deftly_adhoc(export))]
        pub enum AnyEvent #lifetime {
            #(#variants,)*
        }

        impl #lifetime crate::events::PayloadToBytes for AnyEvent #lifetime {
            #[inline]
            fn binary_size(&self) -> usize {
                match self {
                    #(#variants_binary_size)*
                }
            }

            fn write<W: std::io::Write>(&self, metadata: &crate::events::EventMetadata, writer: W) -> std::io::Result<()> {
                match self {
                    #(#variants_to_bytes)*
                }
            }
        }

        impl #lifetime ::std::fmt::Debug for AnyEvent #lifetime {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match self {
                    #(#variant_fmts)*
                }
            }
        }
    )
}

fn event_type_enum(events: &Events) -> proc_macro2::TokenStream {
    let type_variants = events.type_variants();

    quote!(
        use num_derive::FromPrimitive;
        #[derive(Debug)]
        #[derive(FromPrimitive)]
        #[allow(non_camel_case_types)]
        #[repr(u16)]
        pub enum EventType {
            #(#type_variants,)*
        }
    )
}

fn raw_event_load_any(events: &Events) -> proc_macro2::TokenStream {
    let matches = events.enum_matches();

    quote!(
        impl<'e> crate::events::RawEvent<'e> {
            pub fn load_any(&self) -> Result<crate::events::Event<AnyEvent<'e>>, crate::events::PayloadFromBytesError> {
                use crate::events::FromRawEvent;

                let any: AnyEvent = match self.event_type as u32 {
                    #(#matches,)*
                    other => return Err(crate::events::PayloadFromBytesError::UnsupportedEventType(other)),
                };

                Ok(crate::events::Event {
                    metadata: self.metadata.clone(),
                    params: any,
                })
            }
        }
    )
}

pub fn event_info(input: TokenStream) -> TokenStream {
    let events = parse_macro_input!(input as Events);

    let event_info_borrowed = event_info_variant(&events);
    let event_type_enum = event_type_enum(&events);
    let raw_event_load_any = raw_event_load_any(&events);

    quote!(
        #event_info_borrowed
        #event_type_enum
        #raw_event_load_any
    )
    .into()
}
