use falco_plugin_api::ss_plugin_table_t;

#[derive(Debug)]
pub struct RuntimeTableValidator {
    table: *mut ss_plugin_table_t,
}

impl RuntimeTableValidator {
    pub fn new(table: *mut ss_plugin_table_t) -> Self {
        Self { table }
    }

    pub fn check(&self, table: *mut ss_plugin_table_t) -> Result<(), anyhow::Error> {
        match self.table.is_null() {
            true => Ok(()),
            false if self.table == table => Ok(()),
            _ => Err(anyhow::anyhow!(
                "Field comes from a different table than entry"
            )),
        }
    }
}
