// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 ring-3 FP/SIMD state: one XSAVE area per task slot (Kconfig
//! `X86_XSAVE_AREA_BYTES`), saved when a context switch leaves it live and
//! restored on the way back to ring 3. Never a #NM trap
//! (`azos_arch::fpu`'s module doc: LazyFP).
//!
//! `PerCpu::fp_live` (`%gs:` in the asm) names the area whose state is in
//! this CPU's registers, 0 when none:
//!
//! * `context_switch.S`: live and an outgoing task -> `x86_64_fp_save`
//!   into that area; live is cleared either way.
//! * `trap_entry.S`, every return to ring 3 with live == 0 ->
//!   [`x86_64_fp_restore`]: the current task's area (its initial image the
//!   first time) into the registers, live = that area.
//!
//! The kernel is soft-float, so between those two points nothing touches
//! the registers, and a switch to a kernel task and back costs one save and
//! one restore, no more than an eager pair would.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use azos_arch::fpu;

/// Bytes of one area (Kconfig `X86_XSAVE_AREA_BYTES`).
pub(crate) const AREA_BYTES: usize = azos_limits::X86_XSAVE_AREA_BYTES;
const _: () = assert!(AREA_BYTES % fpu::AREA_ALIGN == 0, "X86_XSAVE_AREA_BYTES must be a multiple of 64");
const _: () = assert!(AREA_BYTES >= fpu::LEGACY_BYTES + fpu::XSAVE_HEADER_BYTES);

const SLOTS: usize = azos_sched::MAX_TASKS;

#[repr(C, align(64))]
struct FpArea {
    bytes: [u8; AREA_BYTES],
    /// The tid whose state `bytes` holds; 0 = none (init image on next use).
    tid: u32,
}

const _: () = assert!(core::mem::offset_of!(FpArea, bytes) == 0);

struct Areas(UnsafeCell<[FpArea; SLOTS]>);
// SAFETY: an area is touched only by the CPU running its task, with
// interrupts masked (restore on the way to ring 3, the fork snapshot, exec's
// discard) or by that task's own `context_switch`, which ends before the
// task can run anywhere else (`context_saving`, crates/core/sched).
unsafe impl Sync for Areas {}

static AREAS: Areas = Areas(UnsafeCell::new([const { FpArea { bytes: [0; AREA_BYTES], tid: 0 } }; SLOTS]));

/// Restores done on the way to ring 3 (diagnostics).
pub static RESTORES: AtomicU64 = AtomicU64::new(0);

/// Interrupts masked for the guard's lifetime.
struct IrqMask(azos_arch::InterruptState);
impl IrqMask {
    fn new() -> Self {
        use azos_arch::Interrupts;
        IrqMask(azos_arch::ARCH.disable_all())
    }
}
impl Drop for IrqMask {
    fn drop(&mut self) {
        use azos_arch::Interrupts;
        azos_arch::ARCH.restore(self.0);
    }
}

fn percpu() -> *mut azos_arch::cpu::PerCpu {
    azos_arch::cpu::percpu_area(azos_arch::cpu::percpu_id())
}

fn live() -> u64 {
    // SAFETY: this CPU's own area; a plain word.
    unsafe { (&raw const (*percpu()).fp_live).read_volatile() }
}

fn set_live(v: u64) {
    // SAFETY: as `live`.
    unsafe { (&raw mut (*percpu()).fp_live).write_volatile(v) }
}

fn current_area() -> Option<(*mut FpArea, u32)> {
    let tid = azos_sched::current_task_tid();
    let idx = azos_sched::idx_for_tid(tid)?;
    if idx >= SLOTS {
        return None;
    }
    // SAFETY: in bounds; exclusive per the `Areas` contract.
    Some((unsafe { (*AREAS.0.get()).as_mut_ptr().add(idx) }, tid))
}

/// Enable FP/SIMD for ring 3 on this CPU and pick the save format; the
/// boot CPU prints the choice.
pub fn init_cpu(cpu: usize) {
    let xsaveopt = azos_arch_api::isa::x86_64::XSAVEOPT.allowed();
    match fpu::init_cpu(AREA_BYTES, xsaveopt) {
        Ok(mode) if cpu == 0 => azos_drv_sys::kprintln!(
            "[FPU] {:?}, XCR0 {:#x}, {} of {} B per task (X86_XSAVE_AREA_BYTES)",
            mode, fpu::xcr0(), fpu::area_bytes(), AREA_BYTES),
        Ok(_) => {}
        Err(e) => panic!("x86_64: FP/SIMD state cannot be saved: {e:?}"),
    }
}

/// `context_switch.S`: save the live state into `area` (the outgoing
/// task's). Interrupts are masked (the scheduler switches with them off).
///
/// # Safety
/// `area` is the `fp_live` value of this CPU: an `FpArea` of the task
/// being switched out.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x86_64_fp_save(area: *mut u8) {
    // SAFETY: per the caller; 64-byte aligned, AREA_BYTES long.
    unsafe { fpu::save_eager(area) };
}

/// `trap_entry.S`, on a return to ring 3 with nothing live: load the
/// current task's state (its initial image if the slot holds another
/// task's or none) and mark it live. Interrupts are masked.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_fp_restore() {
    let Some((area, tid)) = current_area() else { return };
    // SAFETY: the current task's area, IRQs masked (the caller's `cli`).
    unsafe {
        if (*area).tid != tid {
            fpu::init_area(&mut (*area).bytes);
            (*area).tid = tid;
        }
        fpu::restore_eager((*area).bytes.as_ptr());
    }
    set_live(area as u64);
    RESTORES.fetch_add(1, Ordering::Relaxed);
}

/// A fresh image (exec): the next return to ring 3 starts from the
/// initial FP state.
pub fn discard_current() {
    let _m = IrqMask::new();
    let Some((area, _)) = current_area() else { return };
    if live() == area as u64 {
        set_live(0);
    }
    // SAFETY: the current task's area, IRQs masked.
    unsafe { (*area).tid = 0 };
}

/// The current task's ring-3 FP state, for a fork: from the registers when
/// live, else from its area, else the initial image.
pub fn snapshot_current(out: &mut [u8; AREA_BYTES]) {
    let _m = IrqMask::new();
    let Some((area, tid)) = current_area() else {
        fpu::init_area(out);
        return;
    };
    // SAFETY: the current task's area, IRQs masked; `out` is 64-aligned
    // (`ForkRegs::fp` sits at offset 0 of an align(64) struct).
    unsafe {
        if live() == area as u64 {
            fpu::save_eager(out.as_mut_ptr());
        } else if (*area).tid == tid {
            out.copy_from_slice(&(*area).bytes);
        } else {
            fpu::init_area(out);
        }
    }
}

/// A forked child's first entry: `state` becomes its saved state, loaded
/// on the way to ring 3.
pub fn adopt(state: &[u8; AREA_BYTES]) {
    let _m = IrqMask::new();
    let Some((area, tid)) = current_area() else { return };
    if live() == area as u64 {
        set_live(0);
    }
    // SAFETY: the current task's area, IRQs masked, not live.
    unsafe {
        (*area).bytes.copy_from_slice(state);
        (*area).tid = tid;
    }
}
