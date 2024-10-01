use crate::tables::{TABLE_READER_EXT, TABLE_WRITER_EXT};
use falco_plugin_api::{
    plugin_api__bindgen_ty_5, ss_plugin_capture_listen_input, ss_plugin_owner_t, ss_plugin_rc,
    ss_plugin_rc_SS_PLUGIN_FAILURE, ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED,
    ss_plugin_rc_SS_PLUGIN_SUCCESS, ss_plugin_routine_fn_t, ss_plugin_routine_state_t,
    ss_plugin_routine_t, ss_plugin_routine_vtable, ss_plugin_t,
};
use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub struct Routine(
    ss_plugin_routine_fn_t,
    *mut ss_plugin_t,
    *mut ss_plugin_routine_state_t,
);
unsafe impl Send for Routine {}
unsafe impl Sync for Routine {}

impl Routine {
    fn call(&self) -> bool {
        let Some(func) = self.0 else {
            return false;
        };

        unsafe { func(self.1, self.2) != 0 }
    }
}

pub struct CaptureListenPlugin {
    plugin: *mut ss_plugin_t,
    api: *const plugin_api__bindgen_ty_5,

    routines: Arc<Mutex<VecDeque<Box<Routine>>>>,
    background_thread: Option<JoinHandle<()>>,
    shutting_down: Arc<AtomicBool>,
}

impl CaptureListenPlugin {
    pub fn new(plugin: *mut ss_plugin_t, api: *const plugin_api__bindgen_ty_5) -> Self {
        Self {
            plugin,
            api,
            routines: Arc::new(Mutex::new(VecDeque::new())),
            background_thread: None,
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    fn api(&self) -> &plugin_api__bindgen_ty_5 {
        unsafe { &*self.api }
    }

    fn owner(&mut self) -> *mut ss_plugin_owner_t {
        self as *mut _ as *mut _
    }

    fn start_background_thread(&self) -> Option<JoinHandle<()>> {
        if self.background_thread.is_some() {
            return None;
        }

        self.shutting_down.store(false, Relaxed);
        let routines = Arc::clone(&self.routines);
        let flag = Arc::clone(&self.shutting_down);
        Some(std::thread::spawn(move || {
            while !flag.load(Relaxed) {
                let Some(next_routine) = ({
                    let mut routines = routines.lock().unwrap();
                    routines.pop_front()
                }) else {
                    break;
                };

                if next_routine.call() {
                    let mut routines = routines.lock().unwrap();
                    routines.push_back(next_routine);
                }
            }
        }))
    }

    unsafe extern "C-unwind" fn subscribe(
        owner: *mut ss_plugin_owner_t,
        func: ss_plugin_routine_fn_t,
        state: *mut ss_plugin_routine_state_t,
    ) -> *mut ss_plugin_routine_t {
        let Some(this) = (unsafe { (owner as *mut Self).as_mut() }) else {
            return std::ptr::null_mut();
        };
        let mut routine = Box::new(Routine(func, this.plugin, state));
        let ret = routine.as_mut() as *mut _ as *mut ss_plugin_routine_t;

        let mut routines = this.routines.lock().unwrap();
        routines.push_back(routine);
        if let Some(thread) = this.start_background_thread() {
            this.background_thread = Some(thread);
        }

        ret
    }

    unsafe extern "C-unwind" fn unsubscribe(
        owner: *mut ss_plugin_owner_t,
        routine: *mut ss_plugin_routine_t,
    ) -> ss_plugin_rc {
        let Some(this) = (unsafe { (owner as *mut Self).as_mut() }) else {
            return ss_plugin_rc_SS_PLUGIN_FAILURE;
        };
        let mut routines = this.routines.lock().unwrap();
        routines.retain(|r| r.as_ref() as *const _ != routine as *const Routine);

        ss_plugin_rc_SS_PLUGIN_SUCCESS
    }

    pub fn on_capture_start(&mut self) -> Result<(), ss_plugin_rc> {
        let capture_open = self
            .api()
            .capture_open
            .ok_or(ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED)?;

        let mut routine_vtable = ss_plugin_routine_vtable {
            subscribe: Some(Self::subscribe),
            unsubscribe: Some(Self::unsubscribe),
        };
        let listen_input = ss_plugin_capture_listen_input {
            owner: self.owner(),
            routine: &mut routine_vtable,
            table_reader_ext: &TABLE_READER_EXT as *const _ as *mut _,
            table_writer_ext: &TABLE_WRITER_EXT as *const _ as *mut _,
        };
        let rc = unsafe { capture_open(self.plugin, &listen_input) };
        if rc == ss_plugin_rc_SS_PLUGIN_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }

    pub fn on_capture_stop(&mut self) -> Result<(), ss_plugin_rc> {
        let capture_close = self
            .api()
            .capture_close
            .ok_or(ss_plugin_rc_SS_PLUGIN_NOT_SUPPORTED)?;

        let mut routine_vtable = ss_plugin_routine_vtable {
            subscribe: Some(Self::subscribe),
            unsubscribe: Some(Self::unsubscribe),
        };
        let listen_input = ss_plugin_capture_listen_input {
            owner: self.owner(),
            routine: &mut routine_vtable,
            table_reader_ext: &TABLE_READER_EXT as *const _ as *mut _,
            table_writer_ext: &TABLE_WRITER_EXT as *const _ as *mut _,
        };
        let rc = unsafe { capture_close(self.plugin, &listen_input) };
        self.shutting_down.store(true, Relaxed);
        if let Some(thread) = self.background_thread.take() {
            thread.join().map_err(|_| ss_plugin_rc_SS_PLUGIN_FAILURE)?;
        }

        if rc == ss_plugin_rc_SS_PLUGIN_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }
}
