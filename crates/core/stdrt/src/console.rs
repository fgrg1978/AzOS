// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Standard streams: fds 0..2 of the startup block. A closed fd, a handle
//! (a file or a pipe the spawner passed, or the terminal the shell lent the
//! program's job, [`crate::terminal`]) or the console.
//!
//! The results are the native codes (negative); the std overlay turns them
//! into `io::ErrorKind`s. Nothing here is an `errno`.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::pure::FdEntry;
use crate::start::{cap_lookup, fd};
use crate::sys::invoke;
use crate::terminal::{Read, Reader};
use azos_abi::cap::{ty, CapHandle};
use azos_abi::invoke as inv;

/// Largest transfer one call takes (the kernel clamps longer ones).
pub const IO_MAX: usize = 4096;

/// Closed fd (`-EBADF`).
pub const E_BADF: isize = -9;
/// The terminal is not this program's any more (`-EIO`): the shell took the
/// focus back and the terminal server revoked it.
pub const E_IO: isize = -5;
static CONSOLE: AtomicU32 = AtomicU32::new(0);

/// This task's console handle, looked up once (`<= 0` when it holds none).
fn console() -> isize {
    let h = CONSOLE.load(Ordering::Relaxed);
    if h != 0 {
        return h as isize;
    }
    let r = cap_lookup(ty::CONSOLE.raw(), 0);
    if r > 0 {
        CONSOLE.store(r as u32, Ordering::Relaxed);
    }
    r
}

/// Write to fd `n` (0..8): bytes taken (at most [`IO_MAX`]), or negative.
pub fn write(n: u64, buf: &[u8]) -> isize {
    let len = buf.len().min(IO_MAX) as u64;
    match fd(n) {
        FdEntry::Closed => E_BADF,
        FdEntry::Console => {
            let h = console();
            if h <= 0 {
                return h;
            }
            invoke(h as u32, inv::LOG_CONSOLE_WRITE, [buf.as_ptr() as u64, len, 0, 0]).0
        }
        FdEntry::Handle(h) => invoke(h, inv::NODE_WRITE, [buf.as_ptr() as u64, len, 0, 0]).0,
    }
}

/// Read from fd `n`: bytes read (0 at the end), or negative. The console has
/// no read: console input belongs to the terminal server alone (its profile
/// is the only one that lists `LOG_CONSOLE_WAIT`), so a program reads its
/// input from the handle its spawner passed as fd 0, and without one its
/// stdin is closed. A terminal lent to the program's job (an endpoint handle)
/// is read through the `Terminal` interface, until something is typed.
pub fn read(n: u64, buf: &mut [u8]) -> isize {
    let len = buf.len().min(IO_MAX) as u64;
    match fd(n) {
        FdEntry::Closed | FdEntry::Console => E_BADF,
        FdEntry::Handle(h) if is_terminal(h) => read_terminal(h, &mut buf[..len as usize]),
        FdEntry::Handle(h) => invoke(h, inv::NODE_READ, [buf.as_mut_ptr() as u64, len, 0, 0]).0,
    }
}

/// Is handle `h` a terminal (a call capability on an endpoint)?
fn is_terminal(h: u32) -> bool {
    CapHandle::from_raw(h).kind() == ty::ENDPOINT.raw()
}

/// The lent terminal's handle, if fd 0 is one: what `std::os::azos::terminal`
/// sets the mode and asks the size through.
pub fn terminal() -> Option<u32> {
    match fd(0) {
        FdEntry::Handle(h) if is_terminal(h) => Some(h),
        _ => None,
    }
}

/// The terminal's stream, one reader at a time.
struct Stream {
    busy: AtomicBool,
    reader: UnsafeCell<Reader>,
}

// SAFETY: `reader` is reached only by the holder of `busy`.
unsafe impl Sync for Stream {}

static STREAM: Stream = Stream { busy: AtomicBool::new(false), reader: UnsafeCell::new(Reader::new()) };

fn read_terminal(h: u32, buf: &mut [u8]) -> isize {
    while STREAM.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: `busy` is held.
    let r = unsafe { &mut *STREAM.reader.get() };
    let n = loop {
        match r.read(&mut |m| crate::sys::ipc_call(h, m), buf, crate::terminal::JOB_WAIT_MS) {
            Read::Bytes(n) => break n as isize,
            Read::End => break 0,
            Read::Again => continue,
            Read::Gone => break E_IO,
        }
    };
    STREAM.busy.store(false, Ordering::Release);
    n
}

/// Is fd `n` the console?
pub fn is_console(n: u64) -> bool {
    fd(n) == FdEntry::Console
}
