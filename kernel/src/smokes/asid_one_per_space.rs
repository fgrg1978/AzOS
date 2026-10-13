// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest `asid_one_per_space_across_rollover` (N12c, owner decision 10-10:
//! one ASID per address space).
//!
//! A fresh frame stands for the root of a space no hart has installed. It
//! takes an ASID ([`azos_sched::asid::new_root_word`]); the next allocation
//! (an unrelated one) is forced to roll the generation over; then two threads of that space,
//! both still carrying the old word, are re-tagged the way
//! `prepare_switch` re-tags an incoming task ([`azos_sched::asid::switch_word`]).
//! Both must come back with the same ASID, and that ASID must be the one the
//! per-space record (`tlb_gen::SPACES`) holds for the root: what makes an
//! ASID-scoped shootdown (Kconfig `TLB_ASID_SCOPED`) cover the whole space.
//!
//! Canary (runtime): `canary=asid-per-thread` makes a re-tag ignore the
//! record and take a fresh ASID per thread: `not ok` (on any `ASID_BITS`
//! of 2 or more; at 1 every ASID is 1 and the canary cannot show).
//!
//! Where it says nothing: a boot with no ASID bits (QEMU x86_64 microvm has
//! no PCID) returns `ok` without running. riscv64 and aarch64 run it.

use azos_arch::ARCH;
use azos_arch_api::{tlb_gen, ArchPlatform};
use azos_mm::pmm;
use azos_sched::asid;

azos_ktest::ktest_late! {
    fn asid_one_per_space_across_rollover() {
        if !asid::retaining() {
            return Ok(());
        }
        let frame = match pmm::alloc_page() {
            Ok(p) => p,
            Err(_) => return Err("no frame"),
        };
        let root = frame.as_usize();
        let old = asid::new_root_word(root);
        let rolls = asid::asid_rollovers();
        // The forced rollover happens at the next allocation, and a re-tag
        // of `old` allocates nothing while `old` still owns its ASID: an
        // unrelated allocation takes it, so `old` is of the previous
        // generation when its threads are switched in.
        asid::force_rollover_next();
        let _ = asid::alloc_asid();
        let t1 = asid::switch_word(old);
        let t2 = asid::switch_word(old);
        let a1 = ARCH.user_root_asid(t1);
        let a2 = ARCH.user_root_asid(t2);
        let rec = tlb_gen::SPACES.asid_of(ARCH.user_root_frame(old));
        let rolled = asid::asid_rollovers() != rolls;
        let _ = pmm::free_page(frame);
        if !rolled {
            return Err("the forced rollover did not happen");
        }
        if a1 == 0 || a1 != a2 {
            return Err("two threads of one space carry different ASIDs after a rollover");
        }
        if rec != a1 {
            return Err("the space's record does not hold the ASID its threads carry");
        }
        Ok(())
    }
}
