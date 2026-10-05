// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Lazy user FP/SIMD state on aarch64.
//!
//! The kernel is built for `aarch64-unknown-none-softfloat` and never holds
//! a value in V0-V31/FPSR/FPCR (`tools/aarch64_fp_free_check.sh` proves it
//! on the linked ELF). So the trap path does not save or restore the user's
//! FP registers at all; they stay in the hardware across every syscall and
//! interrupt, and move only when a different task needs them:
//!
//! * `CPACR_EL1.FPEN = 0b01` is this hart's resting state: EL1 may use FP
//!   (the save/restore below runs at EL1), EL0 traps with ESR EC `0x07`.
//! * [`first_use`] (the EC `0x07` arm of `aarch64_trap_entry`) loads the
//!   current task's saved state — zeroes for a task that never used FP —
//!   records the task's save area in [`AARCH64_FP_LIVE`] for this hart, and
//!   sets `FPEN = 0b11`. The faulting instruction re-executes on `eret`.
//! * `context_switch` (`asm/context_switch.S`) reads [`AARCH64_FP_LIVE`] for
//!   this hart before anything else: if a user state is live it is saved
//!   into that area (not saved at all when the outgoing slot was already
//!   freed), the entry is cleared and `FPEN` goes back to `0b01`.
//!
//! A task that never executes an FP instruction never takes the trap and
//! never has anything saved. Invariant, per hart: `FPEN == 0b11` if and
//! only if `AARCH64_FP_LIVE[hart] != 0`, and then the hardware registers
//! belong to the task whose area that is, which is the task running here.
//!
//! Areas are indexed by the task's slot in `TASKS[]` and tagged with its
//! TID. A slot reused by a new task (new TID) finds a foreign tag on its
//! first use and starts from zeroed registers, so no FP state crosses from a
//! dead task to a new one. TIDs repeat only after a 2^32 wrap
//! (`crates/core/sched/src/scheduler.rs`, `NEXT_TID`).

#![cfg(target_arch = "aarch64")]

use core::sync::atomic::{AtomicUsize, Ordering};
use azos_arch::fp_state::{restore_fp_state, save_fp_state, FpState};

const SLOTS: usize = azos_sched::MAX_TASKS;

/// One task's saved FP/SIMD state plus the TID it belongs to.
#[repr(C, align(16))]
struct FpArea {
    state: FpState,
    /// TID that owns `state`; 0 = none (TID 0 never names a task).
    tid: u32,
    _pad: [u32; 3],
}

// `context_switch.S` stores through the `FpArea` address with the
// `save_fp_state` layout at offset 0.
const _: () = assert!(core::mem::offset_of!(FpArea, state) == 0);
const _: () = assert!(core::mem::size_of::<FpArea>() % 16 == 0);

struct Areas(core::cell::UnsafeCell<[FpArea; SLOTS]>);
// SAFETY: an area is touched only by the hart running its task (trap arm,
// fork snapshot, exec discard — all with IRQs masked) or by the
// `context_switch` of that task on that hart, which ends before the task can
// run anywhere else (`context_saving`, crates/core/sched).
unsafe impl Sync for Areas {}

static AREAS: Areas = Areas(core::cell::UnsafeCell::new(
    [const { FpArea { state: FpState::zero(), tid: 0, _pad: [0; 3] } }; SLOTS],
));

/// Per hart: address of the [`FpArea`] whose state is live in this hart's
/// V registers with EL0 FP enabled, or 0. Written here with IRQs masked;
/// read and cleared by `context_switch.S` (indexed by `TPIDR_EL1`, the hart
/// id `boot.S` publishes and range-checks against `MAX_HARTS`).
#[unsafe(no_mangle)]
pub static AARCH64_FP_LIVE: [AtomicUsize; crate::MAX_HARTS] =
    [const { AtomicUsize::new(0) }; crate::MAX_HARTS];

/// `CPACR_EL1` values. FPEN is bits [21:20]; ZEN/SMEN stay 0 (SVE/SME trap).
pub const CPACR_EL0_TRAPS: u64 = 0b01 << 20;
const CPACR_NO_TRAP: u64 = 0b11 << 20;

/// Number of EC 0x07 traps taken from EL0 (first FP use after a switch-in).
pub static FIRST_USE_TRAPS: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
fn write_cpacr(v: u64) {
    // No `isb`: EL1 is not trapped in either state, and `eret` to EL0 is a
    // context synchronization event.
    unsafe { core::arch::asm!("msr CPACR_EL1, {0}", in(reg) v, options(nomem, nostack, preserves_flags)) };
}

#[inline(always)]
pub fn read_cpacr() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {0}, CPACR_EL1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Boot, on every hart, after the last `CPACR_EL1` writer that grants EL0
/// FP (`mmu_setup::enable_identity_map`/`enable_kernel_map`): enter the
/// resting state. Returns the read-back value for the boot report.
pub fn set_resting_state() -> u64 {
    write_cpacr(CPACR_EL0_TRAPS);
    unsafe { core::arch::asm!("isb", options(nomem, nostack, preserves_flags)) };
    read_cpacr()
}

/// Masks IRQs for its lifetime, restoring the previous DAIF on drop.
struct IrqMask(u64);
impl IrqMask {
    #[inline(always)]
    fn new() -> Self {
        let daif: u64;
        unsafe {
            core::arch::asm!("mrs {0}, DAIF", "msr DAIFSet, #0x2", out(reg) daif,
                options(nomem, nostack, preserves_flags));
        }
        IrqMask(daif)
    }
}
impl Drop for IrqMask {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { core::arch::asm!("msr DAIF, {0}", in(reg) self.0, options(nomem, nostack, preserves_flags)) };
    }
}

/// The current task's area and TID, or `None` for "no current task".
fn current_area() -> Option<(*mut FpArea, u32)> {
    let tid = azos_sched::current_task_tid();
    let idx = azos_sched::idx_for_tid(tid)?;
    if idx >= SLOTS {
        return None;
    }
    // SAFETY: in bounds; exclusive per the `Areas` contract.
    Some((unsafe { (*AREAS.0.get()).as_mut_ptr().add(idx) }, tid))
}

#[inline(always)]
fn hart() -> usize {
    azos_sched::smp::current_cpu_id()
}

/// EC 0x07 from EL0. Caller runs with IRQs masked (the trap arm never
/// unmasks). Returns `false` if there is no current task to charge the state
/// to — the caller treats that trap as unhandled.
pub fn first_use() -> bool {
    let Some((area, tid)) = current_area() else { return false };
    let h = hart();
    unsafe {
        if (*area).tid != tid {
            (*area).state = FpState::zero();
            (*area).tid = tid;
        }
        restore_fp_state(&(*area).state);
    }
    if let Some(slot) = AARCH64_FP_LIVE.get(h) {
        slot.store(area as usize, Ordering::Relaxed);
    }
    write_cpacr(CPACR_NO_TRAP);
    FIRST_USE_TRAPS.fetch_add(1, Ordering::Relaxed);
    true
}

/// Run `f` with the SIMD registers free for kernel use (wave 13: the SHA-256
/// Cryptographic Extension path, `azos_arch::sha2_ce`). IRQs are masked
/// for the call. A user state live on this hart is saved into its area first
/// and EL0 FP goes back to trapping, so that task's next FP instruction
/// reloads it ([`first_use`]): the kernel's values never reach ring 3, and
/// the user's never get lost. Keep `f` short; the caller bounds its work.
pub fn with_kernel_simd<R>(f: impl FnOnce() -> R) -> R {
    let _m = IrqMask::new();
    if let Some(slot) = AARCH64_FP_LIVE.get(hart()) {
        let live = slot.swap(0, Ordering::Relaxed);
        if live != 0 {
            // SAFETY: `live` is the area of the task running here (the
            // module invariant), and IRQs are masked.
            unsafe { save_fp_state(&mut (*(live as *mut FpArea)).state) };
            write_cpacr(CPACR_EL0_TRAPS);
        }
    }
    f()
}

/// `fork()`: the calling task's current user FP state, for the child.
/// Masks IRQs itself: the syscall arm runs with IRQs enabled (O3.1), and a
/// switch between "is it live here" and the register read would read another
/// task's registers (or none) on another hart.
pub fn snapshot_current() -> FpState {
    let _m = IrqMask::new();
    let mut out = FpState::zero();
    let Some((area, tid)) = current_area() else { return out };
    let live = AARCH64_FP_LIVE.get(hart()).map_or(0, |s| s.load(Ordering::Relaxed));
    unsafe {
        if live == area as usize {
            save_fp_state(&mut out);
        } else if (*area).tid == tid {
            out = (*area).state;
        }
    }
    out
}

/// Wave 13 (signal frames): [`snapshot_current`], or `None` when the
/// current task has no FP state at all (never used the file since its exec).
pub fn snapshot_current_if_used() -> Option<FpState> {
    let _m = IrqMask::new();
    let (area, tid) = current_area()?;
    let live = AARCH64_FP_LIVE.get(hart()).map_or(0, |s| s.load(Ordering::Relaxed));
    let mut out = FpState::zero();
    unsafe {
        if live == area as usize {
            save_fp_state(&mut out);
        } else if (*area).tid == tid {
            out = (*area).state;
        } else {
            return None;
        }
    }
    Some(out)
}

/// `exec`: the new image starts with zeroed FP state. Drops the live state
/// (without saving it) and the area's tag.
pub fn discard_current() {
    let _m = IrqMask::new();
    let Some((area, _tid)) = current_area() else { return };
    if let Some(slot) = AARCH64_FP_LIVE.get(hart()) {
        if slot.load(Ordering::Relaxed) == area as usize {
            slot.store(0, Ordering::Relaxed);
            write_cpacr(CPACR_EL0_TRAPS);
        }
    }
    unsafe { (*area).tid = 0 };
}

/// Fork child, on its own kernel stack before its first return to EL0
/// (`aarch64_enter_user_forked`): install the parent's snapshot as this
/// task's saved state. Nothing is loaded into the registers; the child's
/// first FP instruction traps and loads it, like any task switched in.
/// Loading the registers directly instead would leave the child running
/// with EL0 FP trapped and an untagged save area, so that first trap would
/// replace the parent's state with zeroes.
pub fn adopt(state: &FpState) {
    let _m = IrqMask::new();
    let Some((area, tid)) = current_area() else { return };
    unsafe {
        (*area).state = *state;
        (*area).tid = tid;
    }
}
