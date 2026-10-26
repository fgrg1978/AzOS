// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 saved context (`arch/riscv64/src/firmware.rs`, Kconfig
//! `CPU_IDLE_POWERDOWN` and `CPU_HOTPLUG`): the layout the resume asm reads, the slot
//! that is taken once, and what the idle ladder does with a non-retentive state before and after the
//! kernel has a resume entry.
//!
//! The layout is pinned field by field because `azos_cpu_save_run` and
//! `azos_cpu_resume_restore` (`kernel/src/entry/riscv64/resume.rs`) take their
//! offsets from `offset_of!` of this struct: a field added, reordered or
//! retyped moves them with the asm, but a padding hole or a 4-byte field would
//! make the asm's 8-byte `sd`/`ld` hit the wrong word without a build error.
//!
//! Canary (three buckets). Discriminates: `the_layout_is_all_words_in_asm_order`
//! (a reordered field), `a_non_retentive_state_waits_for_the_resume_entry`
//! (`entry_kind` that ignores the resume entry enters the state on a kernel
//! with no way back: red before `set_resume`). Does not discriminate: the
//! host `hart_suspend_nonretentive` returns `ERR_NOT_SUPPORTED` for want of a
//! hart to save, which the asm path replaces; booting is the testing week.

#[allow(dead_code)]
#[path = "../../../../arch/riscv64/src/firmware.rs"]
mod firmware;

use core::mem::{align_of, offset_of, size_of};
use firmware::*;

const NON_RETENTIVE: u32 = 0x8000_0000;
const NON_RETENTIVE_PLATFORM: u32 = 0x9000_0002;
const RETENTIVE: u32 = 0;

fn st(param: Option<u32>, local_timer_stop: bool) -> SuspendState {
    SuspendState { param, local_timer_stop }
}

#[test]
fn the_layout_is_all_words_in_asm_order() {
    assert_eq!(offset_of!(SaveArea, pending), 0);
    assert_eq!(offset_of!(SaveArea, ra), 8);
    assert_eq!(offset_of!(SaveArea, sp), 16);
    assert_eq!(offset_of!(SaveArea, gp), 24);
    assert_eq!(offset_of!(SaveArea, tp), 32);
    assert_eq!(offset_of!(SaveArea, s), 40);
    assert_eq!(offset_of!(SaveArea, satp), 40 + 12 * 8);
    assert_eq!(offset_of!(SaveArea, stvec), 40 + 12 * 8 + 8);
    assert_eq!(offset_of!(SaveArea, sscratch), 40 + 12 * 8 + 16);
    assert_eq!(offset_of!(SaveArea, sstatus), 40 + 12 * 8 + 24);
    // 21 words, rounded to the 16-byte alignment: no padding word in the middle.
    assert_eq!(size_of::<SaveArea>(), 176);
    assert_eq!(align_of::<SaveArea>(), 16);
}

#[test]
fn every_callee_saved_register_has_a_word() {
    // s0..s11 (12), ra, sp, gp, tp: the registers the C calling convention
    // keeps, plus gp/tp which the kernel parks values in.
    let s = SaveArea::EMPTY;
    assert_eq!(s.s.len(), 12);
}

#[test]
fn the_resume_sentinel_is_no_sbi_error() {
    for e in [0, ERR_FAILED, ERR_NOT_SUPPORTED, ERR_INVALID_PARAM, ERR_DENIED, ERR_INVALID_ADDRESS] {
        assert_ne!(e, RESUMED);
    }
    assert!(RESUMED > 0);
}

#[test]
fn local_timer_stop_stays_out_either_way() {
    assert_eq!(st(Some(NON_RETENTIVE), true).enterable_with_resume(), None);
    assert_eq!(st(Some(NON_RETENTIVE), false).enterable_with_resume(), Some(NON_RETENTIVE));
    // A retentive state is not "with resume": it needs none.
    assert_eq!(st(Some(RETENTIVE), false).enterable_with_resume(), None);
    assert_eq!(st(None, false).enterable_with_resume(), None);
}

#[test]
fn a_non_retentive_state_waits_for_the_resume_entry() {
    let l = IdleLadder::EMPTY;
    let states = [
        st(Some(RETENTIVE), false),
        st(Some(NON_RETENTIVE), false),
        st(Some(NON_RETENTIVE_PLATFORM), true), // timer stops: never
    ];
    assert_eq!(l.install(&states), 0b001, "only the retentive state is enterable on its own");
    // No resume entry yet: the deeper depths fall back to the retentive one.
    assert_eq!(resume_entry(), None);
    assert_eq!(l.entry(2), Some(RETENTIVE));
    assert_eq!(l.entry(3), Some(RETENTIVE));
    assert_eq!(hart_suspend_nonretentive(NON_RETENTIVE), ERR_NOT_SUPPORTED);
    assert_eq!(hart_suspend_nonretentive(RETENTIVE), ERR_INVALID_PARAM);

    // No slots either: a hart cannot be saved, and nothing is pending to restore.
    assert!(resume_area(0).is_null());

    fn hook(_: usize) {}
    let table: &'static mut [SaveArea] = Box::leak((0..4).map(|_| SaveArea::EMPTY).collect::<Vec<_>>().into_boxed_slice());
    let (base, n) = (table.as_mut_ptr(), table.len());
    // SAFETY: the leaked table is valid for the life of the process and only used here.
    unsafe { set_resume(0x8020_0000, hook, base, n) };
    assert_eq!(resume_entry(), Some(0x8020_0000));
    assert!(resume_area(0).is_null(), "nothing was saved");
    // SAFETY: slot 2 of the leaked table.
    unsafe { (*base.add(2)).pending.store(1, core::sync::atomic::Ordering::Relaxed) };
    let a = resume_area(2);
    assert!(core::ptr::eq(a, unsafe { base.add(2) }));
    assert!(resume_area(2).is_null(), "taken: the next start boots as a fresh secondary");
    assert!(resume_area(n).is_null(), "no slot for an id past the table");
    assert_eq!(l.entry(1), Some(RETENTIVE));
    assert_eq!(l.entry(2), Some(NON_RETENTIVE), "the power-down state is entered now, installed before or after");
    assert_eq!(l.entry(3), Some(NON_RETENTIVE), "depth 3 stops the timer: the deepest usable one below it");
    l.retire(NON_RETENTIVE);
    assert_eq!(l.entry(2), Some(RETENTIVE), "retired for good");
}

/// The mask the boot hands the energy model (`idle_powerdown_depths`): bit
/// `d - 1` is a state that loses the hart's context and that the kernel can
/// enter. It must name exactly the depths whose entry is the saved-context
/// path, in every order they are listed: a bit missing lets a real-time hart
/// into a state that loses its context; a bit too many only costs a depth.
/// Discriminates: a mask taken from `live` (the retentive states) instead of
/// `deep` reads 0b001 here.
#[test]
fn the_powerdown_mask_names_the_states_that_lose_the_context() {
    let l = IdleLadder::EMPTY;
    assert_eq!(l.powerdown_mask(), 0, "nothing installed");
    let states = [
        st(Some(RETENTIVE), false),
        st(Some(NON_RETENTIVE), false),
        st(Some(NON_RETENTIVE_PLATFORM), true), // timer stops: not entered, not a context-loss depth
        st(Some(NON_RETENTIVE_PLATFORM), false),
    ];
    assert_eq!(l.install(&states), 0b0001);
    assert_eq!(l.powerdown_mask(), 0b1010);
    // The mask does not wait for the resume entry: a real-time hart is kept
    // out of these depths whether or not the kernel can enter them yet.
    // A retired state leaves the mask, as it leaves the ladder.
    l.retire(NON_RETENTIVE);
    assert_eq!(l.powerdown_mask(), 0b1000);
    // A reinstall replaces it.
    l.install(&[st(Some(RETENTIVE), false)]);
    assert_eq!(l.powerdown_mask(), 0);
}
