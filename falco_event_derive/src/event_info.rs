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
        "PT_SOCKADDR"
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
    fn final_field_type(&self) -> Ident {
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
            name = Ident::new(&format!("{}_", name), name.span());
        }

        name
    }

    fn lifetimes(&self) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
        let field_type = self.final_field_type();

        match lifetime_type(&field_type.to_string()) {
            LifetimeType::Ref => (quote!(&'a), proc_macro2::TokenStream::new()),
            LifetimeType::Generic => (proc_macro2::TokenStream::new(), quote!(<'a>)),
            LifetimeType::None => (
                proc_macro2::TokenStream::new(),
                proc_macro2::TokenStream::new(),
            ),
        }
    }

    fn field_definition(&self) -> proc_macro2::TokenStream {
        let name = self.ident();
        let field_type = self.final_field_type();

        let (field_ref, field_lifetime) = self.lifetimes();
        quote!(#[allow(non_snake_case)] pub #name: Option<#field_ref crate::event_derive::event_field_type:: #field_type #field_lifetime>)
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
    fn typedef(&self) -> proc_macro2::TokenStream {
        let event_code = &self.event_code;
        let event_type = Ident::new(
            &event_code.to_string().replace("PPME_", ""),
            event_code.span(),
        );

        let mut fields = Vec::new();
        let mut wants_lifetime = false;
        let mut field_fmts = Vec::new();
        let mut dirfd_methods = Vec::new();

        if let Some((_, _, args)) = self.args.as_ref() {
            fields = args.iter().map(|arg| arg.field_definition()).collect();
            wants_lifetime = !args.iter().all(|arg| {
                matches!(
                    lifetime_type(&arg.final_field_type().to_string()),
                    LifetimeType::None
                )
            });
            field_fmts = args
                .iter()
                .enumerate()
                .map(|(i, field)| {
                    let name = &field.name;
                    let ident = field.ident();
                    let fmt = &field.field_format;
                    let ty = field.final_field_type();
                    let (field_ref, field_lifetime) = field.lifetimes();

                    let space = if i == 0 {
                        None
                    } else {
                        Some(quote!(fmt.write_char(' ')?;))
                    };

                    quote!(
                        #space
                        fmt.write_str(#name)?;
                        fmt.write_char('=')?;
                        <Option<#field_ref crate::event_derive::event_field_type::#ty #field_lifetime> as
                            crate::event_derive::Format<
                                crate::event_derive::format_type::#fmt
                        >>::format(&self.#ident, fmt)?;
                    )
                })
                .collect();

            dirfd_methods = args.iter().map(|a| a.dirfd_method(self)).collect();
        }

        let lifetime = if wants_lifetime {
            quote!(<'a>)
        } else {
            proc_macro2::TokenStream::new()
        };
        let is_large = self.flags.iter().any(|flag| *flag == "EF_LARGE_PAYLOAD");
        let name = &self.name;

        quote!(
            #[allow(non_camel_case_types)]
            #[derive(BinaryPayload)]
            #[derive(Debug)]
            pub struct #event_code #lifetime {
                #(#fields,)*
            }

            impl #lifetime #event_code #lifetime {
                #(#dirfd_methods)*
            }

            impl #lifetime crate::event_derive::EventPayload for #event_code #lifetime {
                const ID: EventType = EventType:: #event_type;
                const LARGE: bool = #is_large;
                const NAME: &'static str = #name;
            }

            impl #lifetime crate::event_derive::Format<crate::event_derive::format_type::PF_NA> for #event_code #lifetime {
                fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                    use std::fmt::Write;

                    match <Self as crate::event_derive::EventPayload>::direction() {
                        crate::event_derive::EventDirection::Entry => fmt.write_str("> ")?,
                        crate::event_derive::EventDirection::Exit => fmt.write_str("< ")?,
                    }
                    fmt.write_str(#name)?;
                    fmt.write_str(" ")?;

                    #(#field_fmts)*

                    Ok(())
                }
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
        let mut wants_lifetime = false;

        if let Some((_, _, args)) = self.args.as_ref() {
            wants_lifetime = !args.iter().all(|arg| {
                matches!(
                    lifetime_type(&arg.final_field_type().to_string()),
                    LifetimeType::None
                )
            })
        }

        let lifetime = if wants_lifetime {
            quote!(<'a>)
        } else {
            proc_macro2::TokenStream::new()
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
            let params = unsafe {
                if <#event_code as crate::event_derive::EventPayload>::LARGE {
                    <#event_code as crate::event_derive::PayloadFromBytes>::read(self.params::<u32>()?)?
                } else {
                    <#event_code as crate::event_derive::PayloadFromBytes>::read(self.params::<u16>()?)?
                }
            };
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
            AnyEvent::#event_type(inner) => {
                inner.format(fmt)
            }
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
        self.events.iter().map(|e| e.typedef())
    }

    fn type_variants(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.type_variant())
    }

    fn enum_variants(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.enum_variant())
    }

    fn enum_matches(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.enum_match())
    }

    fn variant_fmts(&self) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        self.events.iter().map(|e| e.variant_fmt())
    }
}

pub fn event_info(input: TokenStream) -> TokenStream {
    let events = parse_macro_input!(input as Events);
    let typedefs = events.typedefs();
    let type_variants = events.type_variants();
    let variants = events.enum_variants();
    let matches = events.enum_matches();
    let variant_fmts = events.variant_fmts();

    quote!(
        use falco_event_derive::BinaryPayload;
        use num_derive::FromPrimitive;
        use crate::event_derive::RawEvent;

        #(#typedefs)*

        #[derive(Debug)]
        #[derive(FromPrimitive)]
        #[allow(non_camel_case_types)]
        #[repr(u16)]
        pub enum EventType {
            #(#type_variants,)*
        }

        #[derive(Debug)]
        #[allow(non_camel_case_types)]
        pub enum AnyEvent<'a> {
            #(#variants,)*
        }

        impl<'a> crate::event_derive::Format<crate::event_derive::format_type::PF_NA> for AnyEvent<'a> {
            fn format(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    #(#variant_fmts)*
                }
            }
        }

        impl RawEvent<'_> {
            pub fn load_any(&self) -> crate::event_derive::PayloadFromBytesResult<crate::event_derive::Event<AnyEvent>> {
                let any: AnyEvent = match self.event_type as u32 {
                    #(#matches,)*
                    other => return Err(crate::event_derive::PayloadFromBytesError::UnsupportedEventType(other)),
                };

                Ok(crate::event_derive::Event {
                    metadata: self.metadata.clone(),
                    params: any,
                })
            }
        }
    )
        .into()
}
