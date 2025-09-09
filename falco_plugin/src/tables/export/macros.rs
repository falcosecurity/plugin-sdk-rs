#[doc(hidden)]
#[macro_export]
macro_rules! table_export_expose_internals {
    () => {
        pub mod export {
            pub use $crate::tables::export::field_descriptor::FieldDescriptor;
            pub use $crate::tables::export::field_descriptor::FieldId;
            pub use $crate::tables::export::field_descriptor::FieldRef;
            pub use $crate::tables::export::field_value::dynamic::DynamicFieldValue;
            pub use $crate::tables::export::metadata::HasMetadata;
            pub use $crate::tables::export::metadata::Metadata;
            pub use $crate::tables::export::ref_shared::RefShared;
            pub use $crate::tables::export::traits::Entry;
            pub use $crate::tables::export::traits::TableMetadata;

            pub use $crate::tables::export::static_field_specialization::StaticFieldCheck;
            pub use $crate::tables::export::static_field_specialization::StaticFieldFallback;
            pub use $crate::tables::export::static_field_specialization::StaticFieldGet;
            pub use $crate::tables::export::static_field_specialization::StaticFieldGetFallback;
            pub use $crate::tables::export::static_field_specialization::StaticFieldSet;
            pub use $crate::tables::export::static_field_specialization::StaticFieldSetFallback;

            pub use $crate::tables::import::FieldTypeId;
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! table_export_use_internals {
    () => {
        use $crate::internals::tables::export::DynamicFieldValue;
        use $crate::internals::tables::export::FieldDescriptor;
        use $crate::internals::tables::export::FieldId;
        use $crate::internals::tables::export::FieldRef;
        use $crate::internals::tables::export::FieldTypeId;
        use $crate::internals::tables::export::HasMetadata;
        use $crate::internals::tables::export::Metadata;
        use $crate::internals::tables::export::RefShared;
        use $crate::internals::tables::export::StaticFieldCheck;
        use $crate::internals::tables::export::StaticFieldFallback;
        use $crate::internals::tables::export::StaticFieldGet;
        use $crate::internals::tables::export::StaticFieldGetFallback;
        use $crate::internals::tables::export::StaticFieldSet;
        use $crate::internals::tables::export::StaticFieldSetFallback;
        use $crate::internals::tables::export::TableMetadata;

        use $crate::api::ss_plugin_table_fieldinfo;
        use $crate::phf;
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_export_table_get {
    (
        $self:ident,
        static: $($i:literal: $field_name:ident,)*
    ) => {
        fn get(
            &$self,
            key: FieldId,
            type_id: FieldTypeId,
            out: &mut $crate::api::ss_plugin_state_data,
        ) -> Result<(), $crate::anyhow::Error> {
            match key {
                $(FieldId::Static($i) => StaticFieldGet(&$self.$field_name).static_field_get(type_id, out),)*
                _ => $crate::anyhow::bail!("Unknown field")
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_export_table_set {
    (
        $self:ident,
        static: $($i:literal: $field_name:ident,)*
    ) => {
        fn set(
            &mut $self,
            key: FieldId,
            value: DynamicFieldValue)
            -> std::result::Result<(), $crate::anyhow::Error> {
            match key {
                $(FieldId::Static($i) => StaticFieldSet(&mut $self.$field_name).static_field_set(value),)*
                _ => $crate::anyhow::bail!("Unknown field")
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_export_table {
    (for $name:ident {
        $([$i:literal] $field_tag:literal ($field_name_bstr:literal) as $field_name:ident: $field_type:ty)*
    }) => {
        const _: () = {
            $crate::table_export_use_internals!();

            static STATIC_FIELDS: $crate::phf::Map<&'static [u8], std::option::Option<FieldDescriptor>> = $crate::phf::phf_map! {
                $($field_name_bstr => FieldDescriptor::maybe_new(
                    FieldId::Static($i),
                    StaticFieldCheck::<$field_type>::MAYBE_TYPE_ID,
                    StaticFieldCheck::<$field_type>::READONLY,
                ),)*
            };

            pub struct EntryMetadata {
                $(pub $field_name: <$field_type as HasMetadata>::Metadata,)*
            }

            impl Metadata for EntryMetadata {
                fn new() -> $crate::anyhow::Result<Self> {
                    Ok(Self {
                        $($field_name: Metadata::new()?,)*
                    })
                }
            }

            impl TableMetadata for EntryMetadata {
                fn get_field(&self, name: &::std::ffi::CStr) ->
                    std::option::Option<FieldRef>
                {
                    let field = STATIC_FIELDS.get(name.to_bytes_with_nul())?.as_ref()?;
                    Some(FieldRef::Static(field))
                }

                fn add_field(
                    &mut self,
                    name: &std::ffi::CStr,
                    field_type: FieldTypeId,
                    read_only: bool,
                ) ->
                    std::option::Option<FieldRef>
                {
                    None
                }

                fn list_fields(&self) -> std::vec::Vec<ss_plugin_table_fieldinfo> {
                    STATIC_FIELDS
                        .entries()
                        .filter_map(|(name, maybe_field)| {
                            match maybe_field {
                                Some(field) => Some(field.to_raw(name)),
                                None => None,
                            }
                        })
                        .collect()
                }
            }

            impl HasMetadata for $name {
                type Metadata = RefShared<EntryMetadata>;

                fn new_with_metadata(tag: &'static std::ffi::CStr, meta: &Self::Metadata) -> ::std::result::Result<Self, $crate::anyhow::Error> {
                    Ok(Self {
                       $($field_name: HasMetadata::new_with_metadata($field_tag, &meta.read().$field_name)?,)*
                    })
                }
            }

            impl $crate::internals::tables::export::Entry for $name {
                $crate::impl_export_table_get!(
                    self,
                    static: $($i: $field_name,)*
                );
                $crate::impl_export_table_set!(
                    self,
                    static: $($i: $field_name,)*
                );
            }
        };
    };
}
