// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The riscv32 machine layer: `mtime`/`mtimecmp` on the CLINT, the 16550
//! console, the PMP CSRs, and the copy from a task's memory. The kernel
//! reaches all of it through [`Hw`](crate::kernel::Hw); the encodings are
//! `pmp_core`'s.

use core::arch::asm;

use crate::config::*;
use crate::kernel::Hw;
use crate::pmp_core::{self, PmpEntry};

const CLINT: usize = azos_limits::MICRO_CLINT_BASE;
const MTIME: usize = CLINT + 0xBFF8;
const MTIMECMP: usize = CLINT + 0x4000;
const UART: usize = azos_limits::MICRO_UART_BASE;

/// The one machine.
pub struct Machine;

fn rd(addr: usize) -> u32 {
    // SAFETY: a CLINT register of the chip (MICRO_CLINT_BASE).
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn wr(addr: usize, v: u32) {
    // SAFETY: a device register of the chip.
    unsafe { core::ptr::write_volatile(addr as *mut u32, v) }
}

/// `mtime`, read so a carry between the two halves cannot tear it.
pub fn mtime() -> u64 {
    loop {
        let hi = rd(MTIME + 4);
        let lo = rd(MTIME);
        if rd(MTIME + 4) == hi {
            return ((hi as u64) << 32) | lo as u64;
        }
    }
}

/// Arm the timer interrupt for `at` (an `mtime` value), the spec's
/// tear-free order: high half to all ones, then low, then high.
pub fn arm_timer(at: u64) {
    wr(MTIMECMP + 4, u32::MAX);
    wr(MTIMECMP, at as u32);
    wr(MTIMECMP + 4, (at >> 32) as u32);
}

/// Write bytes to the UART, polling the transmitter (LF becomes CR LF).
pub fn uart_write(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            uart_byte(b'\r');
        }
        uart_byte(b);
    }
}

fn uart_byte(b: u8) {
    // SAFETY: the 16550 at MICRO_UART_BASE: LSR (+5) bit 5 is "transmitter
    // holding register empty", THR is +0.
    unsafe {
        while core::ptr::read_volatile((UART + 5) as *const u8) & 0x20 == 0 {}
        core::ptr::write_volatile(UART as *mut u8, b);
    }
}

macro_rules! write_csr_n {
    ($name:literal, $i:expr, $v:expr; $($n:literal)*) => {
        match $i {
            $( $n => unsafe { asm!(concat!("csrw ", $name, $n, ", {0}"), in(reg) $v, options(nostack)) }, )*
            _ => {}
        }
    };
}

fn write_pmpaddr(i: usize, v: usize) {
    write_csr_n!("pmpaddr", i, v;
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63);
}

fn write_pmpcfg(i: usize, v: usize) {
    write_csr_n!("pmpcfg", i, v; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
}

impl Hw for Machine {
    fn now(&self) -> u64 {
        mtime()
    }

    fn console(&mut self, bytes: &[u8]) {
        uart_write(bytes);
    }

    fn program_pmp(&mut self, table: &[PmpEntry; PMP_ENTRIES]) {
        // Switch every entry off first: a half-written table is never a
        // permissive one, whatever order the CSRs are written in.
        let per_word = core::mem::size_of::<usize>();
        let words = pmp_core::cfg_words(PMP_ENTRIES, per_word);
        for w in 0..words {
            write_pmpcfg(w, 0);
        }
        let mut cfgs = [0u8; PMP_ENTRIES];
        for (i, e) in table.iter().enumerate() {
            write_pmpaddr(i, e.addr);
            cfgs[i] = e.cfg;
        }
        for w in 0..words {
            write_pmpcfg(w, pmp_core::pack_cfg(&cfgs, w, per_word));
        }
    }

    fn read_user(&self, addr: usize, out: &mut [u8]) {
        // SAFETY: the kernel calls this only for a range the task's domain
        // admitted for reading, which lies in RAM or a device window.
        unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), out.len()) }
    }
}
