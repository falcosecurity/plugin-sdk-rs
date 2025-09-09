use crate::error::as_result::WithLastError;
use crate::tables::import::traits::{TableAccess, TableMetadata};
use crate::tables::import::RawTable;
use crate::tables::{Key, TablesInput};
use falco_plugin_api::ss_plugin_state_type;
use std::ffi::CStr;

impl TablesInput<'_> {
    /// # Import a table from the Falco plugin API
    ///
    /// The key type is verified by the plugin API, so this method will return
    /// an error on mismatch
    pub fn get_table<T, K>(&self, name: &CStr) -> Result<T, anyhow::Error>
    where
        T: TableAccess<Key = K>,
        K: Key,
    {
        let table = unsafe {
            (self.get_table)(
                self.owner,
                name.as_ptr().cast(),
                K::TYPE_ID as ss_plugin_state_type,
            )
        };
        if table.is_null() {
            Err(anyhow::anyhow!("Could not get table {:?}", name)).with_last_error(&self.last_error)
        } else {
            // Safety: we pass the data directly from FFI, the framework would never lie to us, right?
            let table = RawTable { table };
            let metadata = T::Metadata::new(&table, self)?;
            Ok(T::new(table, metadata, false))
        }
    }
}
