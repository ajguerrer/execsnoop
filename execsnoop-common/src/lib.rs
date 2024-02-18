#![no_std]

#[cfg(feature = "user")]
pub mod bool;

use core::ffi::CStr;

pub const DEFAULT_MAX_ARGS: u32 = 20;
pub const TOTAL_MAX_ARGS: u32 = 60;
pub const UID_ALL: u32 = u32::MAX;
pub const ARGSIZE: usize = 128;
pub const TASK_COMM_LEN: usize = 16;

/// A event containing process metadata emitted when the process exits
#[repr(C)]
pub struct Event {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub retval: i32,
    pub args_count: i32,
    pub comm: [u8; TASK_COMM_LEN],
    pub args: [[u8; ARGSIZE]; TOTAL_MAX_ARGS as usize],
}

impl Event {
    /// an empty [`Event`] to initialize a eBPF map entry
    pub const EMPTY: Event = Event {
        pid: -1,
        ppid: -1,
        uid: 0,
        retval: -1,
        args_count: 0,
        comm: [0; TASK_COMM_LEN],
        args: [[b'\0'; ARGSIZE]; TOTAL_MAX_ARGS as usize],
    };

    /// command name with conversions from `&`[`CStr`] to `&`[`str`] over the FFI boundary
    pub fn comm(&self) -> &str {
        CStr::from_bytes_until_nul(&self.comm)
            .unwrap()
            .to_str()
            .unwrap()
    }

    /// [`Iterator`] over args with conversions from `&`[`CStr`] to `&`[`str`] over the FFI boundary
    pub fn args(&self) -> impl Iterator<Item = &'_ str> {
        self.args
            .iter()
            .take(self.args_count as usize)
            .map(|arg| CStr::from_bytes_until_nul(arg).unwrap().to_str().unwrap())
    }
}
