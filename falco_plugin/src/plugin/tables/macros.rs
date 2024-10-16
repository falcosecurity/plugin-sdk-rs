#[doc(hidden)]
#[macro_export]
macro_rules! table_import_expose_internals {
    () => {
        pub use $crate::plugin::tables::data::Key;
        pub use $crate::plugin::tables::data::Value;
        pub use $crate::plugin::tables::traits::Entry;
        pub use $crate::plugin::tables::traits::EntryWrite;
        pub use $crate::plugin::tables::traits::RawFieldValueType;
        pub use $crate::plugin::tables::traits::TableAccess;

        pub use $crate::plugin::tables::traits::TableMetadata;
        pub use $crate::plugin::tables::RawTable;
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! table_import_use_internals {
    () => {
        use $crate::internals::tables::Entry;
        use $crate::internals::tables::EntryWrite;
        use $crate::internals::tables::Key;
        use $crate::internals::tables::RawFieldValueType;
        use $crate::internals::tables::TableAccess;
        use $crate::internals::tables::Value;
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_import_table_metadata {
    (for $meta:ident => { $($access_fn:ident($field:ident, $field_cstr:literal);)* }) => {
        impl $crate::internals::tables::TableMetadata for $meta {
            fn new(
                raw_table: &$crate::internals::tables::RawTable,
                tables_input: &$crate::tables::TablesInput)
            -> $crate::anyhow::Result<Self> {
                Ok(Self {
                    $($field: raw_table.$access_fn(tables_input, $field_cstr)?.into(),)*
                })
            }
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_import_table_accessor_traits {
    ($m:ident: $getter:ident,$table_getter:ident,$setter:ident) => {
        #[allow(non_snake_case)]
        pub mod $m {
            #[allow(non_camel_case_types)]
            pub trait $getter<'a> {
                type TableValue: $crate::internals::tables::Value + ?Sized;
                type EntryValue: 'a;

                fn $getter(
                    &'a self,
                    reader: &impl $crate::tables::TableReader,
                ) -> $crate::anyhow::Result<Self::EntryValue>;
            }

            #[allow(non_camel_case_types)]
            pub trait $table_getter<'a> {
                type Key;
                type Entry;

                fn $table_getter(
                    &'a self,
                    reader: &impl $crate::tables::TableReader,
                    key: &Self::Key,
                ) -> $crate::anyhow::Result<Self::Entry>;
            }

            #[allow(non_camel_case_types)]
            pub trait $setter<'a> {
                type ScalarValue: $crate::internals::tables::Value<AssocData = ()> + ?Sized;

                fn $setter(
                    &'a self,
                    writer: &$crate::tables::TableWriter,
                    value: &Self::ScalarValue,
                ) -> $crate::anyhow::Result<()>;
            }
        }

        // make the traits available without a name, so we can
        // `use the_mod_the_macro_was_called_in::*` without polluting the outer namespace
        pub use $m::$getter as _;
        pub use $m::$setter as _;
        pub use $m::$table_getter as _;
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_import_table_accessor_impls {
    (use $m:path; $field:ident($field_ty:ty) for $entry_ty:ty; meta $meta_ty:ident =>
        $getter:ident,
        $table_getter:ident,
        $setter:ident) => {
        const _: () = {
            $crate::table_import_use_internals!();
            use $m::{$getter, $setter, $table_getter};

            impl<'a> $getter<'a> for $entry_ty {
                type TableValue = <$field_ty as RawFieldValueType>::TableValue;
                type EntryValue = <$field_ty as RawFieldValueType>::EntryValue<'a>;

                fn $getter(
                    &'a self,
                    reader: &impl $crate::tables::TableReader,
                ) -> $crate::anyhow::Result<Self::EntryValue> {
                    let metadata = self.get_metadata();
                    self.read_field(reader, &metadata.$field)
                }
            }

            impl<'a, E> $table_getter<'a> for E
            where
                E: $getter<'a>,
                <E as $getter<'a>>::EntryValue: TableAccess,
                <<E as $getter<'a>>::EntryValue as TableAccess>::Key: Key,
                <<E as $getter<'a>>::EntryValue as TableAccess>::Entry: Entry + 'static,
            {
                type Key = <<E as $getter<'a>>::EntryValue as TableAccess>::Key;
                type Entry = <<E as $getter<'a>>::EntryValue as TableAccess>::Entry;

                fn $table_getter(
                    &'a self,
                    reader: &impl $crate::tables::TableReader,
                    key: &Self::Key,
                ) -> $crate::anyhow::Result<Self::Entry> {
                    let value = self.$getter(reader)?;
                    value.get_entry(reader, key)
                }
            }

            impl<'a, E> $setter<'a> for E
            where
                E: 'a,
                E: $getter<'a>,
                E::TableValue: Value<AssocData = ()>,
                E: EntryWrite<&'a $field_ty, E::TableValue>,
                E: Entry<Metadata = std::sync::Arc<$meta_ty>>,
            {
                type ScalarValue = E::TableValue;

                fn $setter(
                    &'a self,
                    writer: &$crate::tables::TableWriter,
                    value: &Self::ScalarValue,
                ) -> $crate::anyhow::Result<()> {
                    let metadata = self.get_metadata();
                    self.write_field(writer, &metadata.$field, value)
                }
            }
        };
    };
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use crate::plugin::tables::field::Field;
    use crate::plugin::tables::Entry;
    use std::ffi::CStr;
    use std::sync::Arc;

    struct ImportedMeta {
        u64_field: Field<u64, ImportedEntry>,
        string_field: Field<CStr, ImportedEntry>,
    }

    type ImportedEntry = Entry<Arc<ImportedMeta>>;

    impl_import_table_metadata!(for ImportedMeta => {
        get_field(u64_field, c"u64_field");
        add_field(string_field, c"string_field");
    });

    mod private {
        impl_import_table_accessor_traits!(__private_ImportedMeta: get_u64_field, get_u64_field_by_key, set_u64_field);
    }

    impl_import_table_accessor_impls!(
        use private::__private_ImportedMeta;
        u64_field(Field<u64, ImportedEntry>) for ImportedEntry; meta ImportedMeta =>
            get_u64_field, get_u64_field_by_key, set_u64_field);
}
