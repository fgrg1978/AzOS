// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Threads over `SYS_THREAD_CREATE` (azos_stdrt::thread): a stack of our own
//! with guard pages, joined by the word the kernel clears at exit.

use crate::ffi::CStr;
use crate::io;
use crate::num::NonZero;
use crate::sys::map_native_error;
use crate::thread::ThreadInit;
use crate::time::Duration;

pub const DEFAULT_MIN_STACK_SIZE: usize = azos_stdrt::thread::DEFAULT_STACK;

pub struct Thread(azos_stdrt::thread::Thread);

impl Thread {
    // unsafe: see thread::Builder::spawn_unchecked for safety requirements
    pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
        extern "C" fn run(arg: usize) {
            // SAFETY: `arg` is the box leaked below, taken once.
            let init = unsafe { Box::from_raw(core::ptr::with_exposed_provenance_mut::<ThreadInit>(arg)) };
            let rust_start = init.init();
            rust_start();
        }

        let arg = Box::into_raw(init).expose_provenance();
        match azos_stdrt::thread::spawn(stack, run, arg) {
            Ok(t) => Ok(Thread(t)),
            Err(code) => {
                // SAFETY: the thread did not start; the box is still ours.
                drop(unsafe { Box::from_raw(core::ptr::with_exposed_provenance_mut::<ThreadInit>(arg)) });
                Err(map_native_error(code))
            }
        }
    }

    pub fn join(self) {
        self.0.join()
    }
}

pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    Err(io::Error::UNKNOWN_THREAD_COUNT)
}

pub fn current_os_id() -> Option<u64> {
    None
}

pub fn yield_now() {
    azos_stdrt::time::yield_now()
}

pub fn set_name(_name: &CStr) {}

pub fn sleep(dur: Duration) {
    let ns = u64::try_from(dur.as_nanos()).unwrap_or(u64::MAX);
    let deadline = azos_stdrt::time::now_ns().saturating_add(ns);
    // The call can return early (a stop request); the clock decides.
    while azos_stdrt::time::now_ns() < deadline {
        azos_stdrt::time::sleep_until(deadline);
    }
}
