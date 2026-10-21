// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 saved context and CPU stop (`crates/core/arch-aarch64/src/firmware.rs`,
//! Kconfig `CPU_IDLE_POWERDOWN` and `CPU_HOTPLUG`): the layout the resume asm
//! reads, the PSCI numbers of the stop, and what the idle ladder does with a
//! power-down state before and after the kernel has a resume entry.
//!
//! Canary (three buckets). Discriminates: `the_layout_is_all_words_in_asm_order`
//! (`azos_cpu_save_run` / `azos_cpu_resume_restore` in
//! `kernel/src/entry/aarch64/resume.rs` take these offsets),
//! `a_power_down_state_waits_for_the_resume_entry` (red before `set_resume`
//! if the ladder ignores the entry). Does not discriminate: the host
//! `cpu_suspend_powerdown` answers `PSCI_NOT_SUPPORTED`; booting is the
//! testing week.

// Its own copy of the module: the resume entry is process-wide state, and the
// ladder tests of `idle_deep` (the shared copy) assert a kernel with none.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/firmware.rs"]
mod firmware;

use firmware::*;
use core::mem::{align_of, offset_of, size_of};

const O: PowerStateFormat = PowerStateFormat::Original;
const STANDBY: u32 = 0x0000_0000;
const POWERDOWN: u32 = 0x0001_0033;
const POWERDOWN2: u32 = 0x0001_0044;

fn st(param: Option<u32>, local_timer_stop: bool) -> SuspendState {
    SuspendState { param, local_timer_stop }
}

#[test]
fn the_layout_is_all_words_in_asm_order() {
    assert_eq!(offset_of!(SaveArea, pending), 0);
    assert_eq!(offset_of!(SaveArea, x), 8);
    assert_eq!(offset_of!(SaveArea, lr), 8 + 11 * 8);
    assert_eq!(offset_of!(SaveArea, sp), 8 + 12 * 8);
    assert_eq!(offset_of!(SaveArea, sp_el0), 8 + 13 * 8);
    assert_eq!(offset_of!(SaveArea, ttbr0), 8 + 14 * 8);
    assert_eq!(offset_of!(SaveArea, tpidr_el0), 8 + 15 * 8);
    assert_eq!(offset_of!(SaveArea, tpidrro_el0), 8 + 16 * 8);
    assert_eq!(offset_of!(SaveArea, contextidr), 8 + 17 * 8);
    // 19 words, rounded to the 16-byte alignment (the asm cleans whole lines).
    assert_eq!(size_of::<SaveArea>(), 160);
    assert_eq!(align_of::<SaveArea>(), 16);
}

#[test]
fn x19_to_x29_have_a_word_each() {
    assert_eq!(SaveArea::EMPTY.x.len(), 11);
}

#[test]
fn the_stop_calls_are_psci_0_2() {
    assert_eq!(PSCI_CPU_OFF, 0x8400_0002);
    assert_eq!(PSCI_AFFINITY_INFO_64, 0xC400_0004);
    assert_eq!(AFFINITY_ON, 0);
    assert_eq!(AFFINITY_OFF, 1);
    assert!(!psci_has_cpu_off(-1), "PSCI_VERSION itself not implemented");
    assert!(!psci_has_cpu_off(0x0000_0001), "0.1 has no AFFINITY_INFO");
    assert!(psci_has_cpu_off(0x0000_0002));
    assert!(psci_has_cpu_off(0x0001_0000), "1.0");
}

#[test]
fn the_resume_sentinel_is_no_psci_code() {
    for e in [PSCI_OK, PSCI_NOT_SUPPORTED, PSCI_INVALID_PARAMS, PSCI_DENIED, PSCI_ALREADY_ON,
              PSCI_ON_PENDING, PSCI_INTERNAL_FAILURE, PSCI_NOT_PRESENT, PSCI_DISABLED, PSCI_INVALID_ADDRESS] {
        assert_ne!(e as isize, RESUMED);
    }
}

#[test]
fn local_timer_stop_stays_out_either_way() {
    assert_eq!(st(Some(POWERDOWN), true).enterable_with_resume(O), None);
    assert_eq!(st(Some(POWERDOWN), false).enterable_with_resume(O), Some(POWERDOWN));
    // A standby state is not "with resume": it needs none.
    assert_eq!(st(Some(STANDBY), false).enterable_with_resume(O), None);
    assert_eq!(st(None, false).enterable_with_resume(O), None);
}

#[test]
fn a_power_down_state_waits_for_the_resume_entry() {
    let l = IdleLadder::EMPTY;
    let states = [
        st(Some(STANDBY), false),
        st(Some(POWERDOWN), false),
        st(Some(POWERDOWN2), true), // timer stops: never
    ];
    assert_eq!(l.install(&states, O), 0b001, "only the standby state is enterable on its own");
    assert_eq!(resume_entry(), None);
    assert_eq!(l.entry(2), Some(STANDBY));
    assert_eq!(l.entry(3), Some(STANDBY));
    assert_eq!(cpu_suspend_powerdown(POWERDOWN), PSCI_NOT_SUPPORTED);

    fn hook(_: usize) {}
    fn prepare(_: usize) {}
    let mut slots = [SaveArea::EMPTY, SaveArea::EMPTY];
    // SAFETY: the slots outlive the test and nothing else uses them (the host has no PE to save).
    unsafe { set_resume(0x4020_0000, hook, prepare, slots.as_mut_ptr(), slots.len()) };
    assert_eq!(resume_entry(), Some(0x4020_0000));
    assert_eq!(l.entry(1), Some(STANDBY));
    assert_eq!(l.entry(2), Some(POWERDOWN), "the power-down state is entered now, installed before or after");
    assert_eq!(l.entry(3), Some(POWERDOWN), "depth 3 stops the timer: the deepest usable one below it");
    l.retire(POWERDOWN);
    assert_eq!(l.entry(2), Some(STANDBY), "retired for good");
}

/// The mask the boot hands the energy model (`idle_powerdown_depths`): bit
/// `d - 1` is a power-down state the kernel can enter. Which states those are
/// depends on the firmware's `power_state` format, which only the arch knows:
/// the same word is a power-down state in the original format (StateType bit
/// 16) and a standby state in the extended one (bit 30). A bit missing lets a
/// real-time CPU into a state that loses its context. Discriminates: a mask
/// taken from the retentive states, or one that ignores the format.
#[test]
fn the_powerdown_mask_names_the_states_that_lose_the_context() {
    let l = IdleLadder::EMPTY;
    assert_eq!(l.powerdown_mask(), 0, "nothing installed");
    let states = [
        st(Some(STANDBY), false),
        st(Some(POWERDOWN), false),
        st(Some(POWERDOWN2), true), // timer stops: not entered, not a context-loss depth
        st(Some(POWERDOWN2), false),
    ];
    assert_eq!(l.install(&states, O), 0b0001);
    assert_eq!(l.powerdown_mask(), 0b1010);
    // The same words under the extended format: bit 16 is a StateID bit there,
    // so they are standby states, and nothing loses the context.
    let x = IdleLadder::EMPTY;
    assert_eq!(x.install(&states, PowerStateFormat::Extended), 0b1011);
    assert_eq!(x.powerdown_mask(), 0);
    // A retired state leaves the mask, as it leaves the ladder.
    l.retire(POWERDOWN);
    assert_eq!(l.powerdown_mask(), 0b1000);
}
