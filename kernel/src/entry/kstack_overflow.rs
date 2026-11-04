// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A kernel stack overflow, caught at trap entry (riscv64, aarch64: the
//! stack bit test in `trap_entry.S`; x86_64 takes #DF on its IST stack). The
//! trap would have stored its frame in the guard below a task stack and
//! faulted again forever, so it runs on a stack of its own instead.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Bytes of each CPU's stack for the report.
const OVF: usize = 16 << 10;

/// Per CPU, the top of its overflow stack (0: none yet; the trap entry then
/// stops the CPU where it is). A word per CPU; the stacks are frames.
#[no_mangle]
pub static AZOS_KSTACK_OVF_TOP: [AtomicUsize; crate::MAX_HARTS] = [const { AtomicUsize::new(0) }; crate::MAX_HARTS];

/// Give every possible CPU its overflow stack, from the frame allocator.
/// With the per-CPU areas, before the first task.
pub(crate) fn setup() {
    let pages = OVF.div_ceil(1 << azos_limits::PAGE_SHIFT);
    for cpu in azos_percpu::possible().iter() {
        if cpu >= crate::MAX_HARTS { continue; }
        match azos_mm::pmm::alloc_contiguous(pages) {
            Ok(pa) => AZOS_KSTACK_OVF_TOP[cpu].store(azos_mm::addr::phys_to_virt(pa.as_usize()) + OVF, Ordering::Release),
            Err(_) => azos_drv_sys::kwarn!("[KSTACK] no overflow stack for CPU {}: an overflow there stops it unreported", cpu),
        }
    }
}

/// The report: the trapping PC, the SP that ran off its stack, the fault
/// address. Never returns.
#[no_mangle]
pub extern "C" fn azos_kstack_overflow(pc: usize, sp: usize, addr: usize) -> ! {
    panic!("kernel stack overflow: pc {:#x}, sp {:#x} below the stack of slot {}, fault at {:#x}",
           pc, sp, azos_mm::kstack::slot_holding(sp + azos_mm::kstack::STRIDE / 2), addr);
}
