// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `FAULTER.ELF`: started by `CAPTEST.ELF` to be refused. It holds no
//! device and no pipeline, so a store into the code window (readable and
//! executable, not writable) must trap and the kernel must end it; the
//! store after it is never reached. The kernel's `fault` line is what the
//! gate looks for.

use super::sys;

pub extern "C" fn main(_region: usize, _info: usize) -> ! {
    sys::print(b"[FAULTER] storing into the code window\n");
    // SAFETY: deliberately not: the PMP entry for the window has no W.
    unsafe { core::ptr::write_volatile(azos_limits::MICRO_RAM_BASE as *mut u32, 0) };
    sys::print(b"[FAULTER] FAIL the store was not refused\n");
    sys::exit(3)
}
