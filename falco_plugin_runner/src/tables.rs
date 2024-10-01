use falco_plugin_api::{
    ss_plugin_bool, ss_plugin_rc, ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_SUCCESS,
    ss_plugin_state_data, ss_plugin_state_type, ss_plugin_table_entry_t, ss_plugin_table_field_t,
    ss_plugin_table_fieldinfo, ss_plugin_table_fields_vtable_ext, ss_plugin_table_info,
    ss_plugin_table_input, ss_plugin_table_iterator_func_t, ss_plugin_table_iterator_state_t,
    ss_plugin_table_reader_vtable_ext, ss_plugin_table_t, ss_plugin_table_writer_vtable_ext,
};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::ffi::{c_char, CStr, CString};

pub struct Tables {
    tables: BTreeMap<CString, Box<ss_plugin_table_input>>,
    reader_ext_store: Vec<ss_plugin_table_reader_vtable_ext>,
    writer_ext_store: Vec<ss_plugin_table_writer_vtable_ext>,
    fields_ext_store: Vec<ss_plugin_table_fields_vtable_ext>,
    table_info_cache: Vec<ss_plugin_table_info>,
}

macro_rules! delegate_table_method {
    ($table:expr => $vtable:ident . $method:ident or $error:expr) => {{
        let table_input = $table as *mut ss_plugin_table_input;
        let table_input = unsafe { table_input.as_mut() };
        let Some(table_input) = table_input else {
            #[allow(clippy::unused_unit)]
            return $error;
        };

        let Some(vtable) = table_input.$vtable.as_ref() else {
            #[allow(clippy::unused_unit)]
            return $error;
        };

        let Some(method) = vtable.$method else {
            #[allow(clippy::unused_unit)]
            return $error;
        };

        (method, table_input.table)
    }};
}

unsafe extern "C-unwind" fn get_table_name(table: *mut ss_plugin_table_t) -> *const c_char {
    let (get_table_name, table) =
        delegate_table_method!(table => reader_ext.get_table_name or std::ptr::null());
    get_table_name(table)
}

unsafe extern "C-unwind" fn get_table_size(table: *mut ss_plugin_table_t) -> u64 {
    let (get_table_size, table) = delegate_table_method!(table => reader_ext.get_table_size or 0);
    get_table_size(table)
}

unsafe extern "C-unwind" fn get_table_entry(
    table: *mut ss_plugin_table_t,
    key: *const ss_plugin_state_data,
) -> *mut ss_plugin_table_entry_t {
    let (get_table_entry, table) =
        delegate_table_method!(table => reader_ext.get_table_entry or std::ptr::null_mut());
    get_table_entry(table, key)
}

unsafe extern "C-unwind" fn read_entry_field(
    table: *mut ss_plugin_table_t,
    entry: *mut ss_plugin_table_entry_t,
    field: *const ss_plugin_table_field_t,
    out: *mut ss_plugin_state_data,
) -> ss_plugin_rc {
    let (read_entry_field, table) = delegate_table_method!(table => reader_ext.read_entry_field or ss_plugin_rc_SS_PLUGIN_FAILURE);
    read_entry_field(table, entry, field, out)
}

unsafe extern "C-unwind" fn release_table_entry(
    table: *mut ss_plugin_table_t,
    entry: *mut ss_plugin_table_entry_t,
) {
    let (release_table_entry, table) =
        delegate_table_method!(table => reader_ext.release_table_entry or ());
    release_table_entry(table, entry)
}

unsafe extern "C-unwind" fn iterate_entries(
    table: *mut ss_plugin_table_t,
    iter: ss_plugin_table_iterator_func_t,
    state: *mut ss_plugin_table_iterator_state_t,
) -> ss_plugin_bool {
    let (iterate_entries, table) = delegate_table_method!(table => reader_ext.iterate_entries or 0);
    iterate_entries(table, iter, state)
}

unsafe extern "C-unwind" fn clear_table(table: *mut ss_plugin_table_t) -> ss_plugin_rc {
    let (clear_table, table) =
        delegate_table_method!(table => writer_ext.clear_table or ss_plugin_rc_SS_PLUGIN_FAILURE);
    clear_table(table)
}

unsafe extern "C-unwind" fn erase_table_entry(
    table: *mut ss_plugin_table_t,
    key: *const ss_plugin_state_data,
) -> ss_plugin_rc {
    let (erase_table_entry, table) = delegate_table_method!(table => writer_ext.erase_table_entry or ss_plugin_rc_SS_PLUGIN_FAILURE);
    erase_table_entry(table, key)
}

unsafe extern "C-unwind" fn create_table_entry(
    table: *mut ss_plugin_table_t,
) -> *mut ss_plugin_table_entry_t {
    let (create_table_entry, table) =
        delegate_table_method!(table => writer_ext.create_table_entry or std::ptr::null_mut());
    create_table_entry(table)
}

unsafe extern "C-unwind" fn destroy_table_entry(
    table: *mut ss_plugin_table_t,
    entry: *mut ss_plugin_table_entry_t,
) {
    let (destroy_table_entry, table) =
        delegate_table_method!(table => writer_ext.destroy_table_entry or ());
    destroy_table_entry(table, entry)
}

unsafe extern "C-unwind" fn add_table_entry(
    table: *mut ss_plugin_table_t,
    key: *const ss_plugin_state_data,
    entry: *mut ss_plugin_table_entry_t,
) -> *mut ss_plugin_table_entry_t {
    let (add_table_entry, table) =
        delegate_table_method!(table => writer_ext.add_table_entry or std::ptr::null_mut());
    add_table_entry(table, key, entry)
}

unsafe extern "C-unwind" fn write_entry_field(
    table: *mut ss_plugin_table_t,
    entry: *mut ss_plugin_table_entry_t,
    field: *const ss_plugin_table_field_t,
    value: *const ss_plugin_state_data,
) -> ss_plugin_rc {
    let (write_entry_field, table) = delegate_table_method!(table => writer_ext.write_entry_field or ss_plugin_rc_SS_PLUGIN_FAILURE);
    write_entry_field(table, entry, field, value)
}

unsafe extern "C-unwind" fn list_table_fields(
    table: *mut ss_plugin_table_t,
    nfields: *mut u32,
) -> *const ss_plugin_table_fieldinfo {
    let (list_table_fields, table) =
        delegate_table_method!(table => fields_ext.list_table_fields or std::ptr::null());
    list_table_fields(table, nfields)
}

unsafe extern "C-unwind" fn get_table_field(
    table: *mut ss_plugin_table_t,
    name: *const c_char,
    data_type: ss_plugin_state_type,
) -> *mut ss_plugin_table_field_t {
    let (get_table_field, table) =
        delegate_table_method!(table => fields_ext.get_table_field or std::ptr::null_mut());
    get_table_field(table, name, data_type)
}

unsafe extern "C-unwind" fn add_table_field(
    table: *mut ss_plugin_table_t,
    name: *const c_char,
    data_type: ss_plugin_state_type,
) -> *mut ss_plugin_table_field_t {
    let (add_table_field, table) =
        delegate_table_method!(table => fields_ext.add_table_field or std::ptr::null_mut());
    add_table_field(table, name, data_type)
}

pub static TABLE_READER: falco_plugin_api::ss_plugin_table_reader_vtable =
    falco_plugin_api::ss_plugin_table_reader_vtable {
        get_table_name: Some(get_table_name),
        get_table_size: Some(get_table_size),
        get_table_entry: Some(get_table_entry),
        read_entry_field: Some(read_entry_field),
    };

pub static TABLE_READER_EXT: falco_plugin_api::ss_plugin_table_reader_vtable_ext =
    falco_plugin_api::ss_plugin_table_reader_vtable_ext {
        get_table_name: Some(get_table_name),
        get_table_size: Some(get_table_size),
        get_table_entry: Some(get_table_entry),
        read_entry_field: Some(read_entry_field),
        release_table_entry: Some(release_table_entry),
        iterate_entries: Some(iterate_entries),
    };

pub static TABLE_WRITER: falco_plugin_api::ss_plugin_table_writer_vtable =
    falco_plugin_api::ss_plugin_table_writer_vtable {
        clear_table: Some(clear_table),
        erase_table_entry: Some(erase_table_entry),
        create_table_entry: Some(create_table_entry),
        destroy_table_entry: Some(destroy_table_entry),
        add_table_entry: Some(add_table_entry),
        write_entry_field: Some(write_entry_field),
    };

pub static TABLE_WRITER_EXT: falco_plugin_api::ss_plugin_table_writer_vtable_ext =
    falco_plugin_api::ss_plugin_table_writer_vtable_ext {
        clear_table: Some(clear_table),
        erase_table_entry: Some(erase_table_entry),
        create_table_entry: Some(create_table_entry),
        destroy_table_entry: Some(destroy_table_entry),
        add_table_entry: Some(add_table_entry),
        write_entry_field: Some(write_entry_field),
    };

pub static TABLE_FIELDS: falco_plugin_api::ss_plugin_table_fields_vtable =
    falco_plugin_api::ss_plugin_table_fields_vtable {
        list_table_fields: Some(list_table_fields),
        get_table_field: Some(get_table_field),
        add_table_field: Some(add_table_field),
    };

pub static TABLE_FIELDS_EXT: falco_plugin_api::ss_plugin_table_fields_vtable_ext =
    falco_plugin_api::ss_plugin_table_fields_vtable_ext {
        list_table_fields: Some(list_table_fields),
        get_table_field: Some(get_table_field),
        add_table_field: Some(add_table_field),
    };

impl Default for Tables {
    fn default() -> Self {
        Self::new()
    }
}

impl Tables {
    pub fn new() -> Self {
        Self {
            tables: BTreeMap::new(),
            reader_ext_store: Vec::new(),
            writer_ext_store: Vec::new(),
            fields_ext_store: Vec::new(),
            table_info_cache: Vec::new(),
        }
    }

    pub fn list_tables(&mut self) -> &mut Vec<ss_plugin_table_info> {
        if self.table_info_cache.is_empty() {
            for (name, table) in self.tables.iter() {
                self.table_info_cache.push(ss_plugin_table_info {
                    name: name.as_ptr(),
                    key_type: table.key_type,
                })
            }
        }

        &mut self.table_info_cache
    }

    pub fn get_table(
        &self,
        name: &CStr,
        key_type: ss_plugin_state_type,
    ) -> Option<&ss_plugin_table_input> {
        let table = self.tables.get(name)?;
        if table.key_type != key_type {
            return None;
        }
        Some(table)
    }

    pub fn add_table(&mut self, name: &CStr, table_input: &ss_plugin_table_input) -> ss_plugin_rc {
        match self.tables.entry(CString::from(name)) {
            Entry::Occupied(entry) => {
                let table = entry.get();
                if table.key_type != table_input.key_type {
                    return ss_plugin_rc_SS_PLUGIN_FAILURE;
                }
                ss_plugin_rc_SS_PLUGIN_SUCCESS
            }
            Entry::Vacant(entry) => {
                self.reader_ext_store
                    .push(unsafe { *table_input.reader_ext });
                let reader_ext = self.reader_ext_store.last().unwrap() as *const _ as *mut _;

                self.writer_ext_store
                    .push(unsafe { *table_input.writer_ext });
                let writer_ext = self.writer_ext_store.last().unwrap() as *const _ as *mut _;

                self.fields_ext_store
                    .push(unsafe { *table_input.fields_ext });
                let fields_ext = self.fields_ext_store.last().unwrap() as *const _ as *mut _;

                let mut table_input = *table_input;
                table_input.reader_ext = reader_ext;
                table_input.writer_ext = writer_ext;
                table_input.fields_ext = fields_ext;

                entry.insert(Box::new(table_input));
                self.table_info_cache.clear();
                ss_plugin_rc_SS_PLUGIN_SUCCESS
            }
        }
    }
}
