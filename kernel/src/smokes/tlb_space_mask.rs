// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest `tlb_space_mask_reaches_the_harts_that_ran` (N12b, Kconfig
//! `TLB_SPACE_MASK`).
//!
//! A fresh frame stands for an address-space root no hart has installed (so
//! the shootdown sends no IPI and touches no live table). Another hart is
//! recorded as having switched into it, through the same call
//! `azos_sched::asid::prepare_switch` makes (`tlb_gen::note_ran`). Then this
//! hart shoots the space down through `ArchPlatform::tlb_shootdown`:
//!   - the table must name exactly that hart for the space;
//!   - the shootdown must have marked it stale (`tlb_gen::LAST_MARKED`).
//! Harts on another generation (an idle hart is STALE from boot) are marked
//! too by design, so the "exactly" half is read from the table.
//!
//! Canary (runtime): `canary=tlb-space-mask-drop` makes switch-ins record
//! nothing, so the table names no hart for the space: `not ok`.
//!
//! Where it says nothing: aarch64 shoots down by broadcast TLBI and keeps no
//! mask (`tlb_space_key` is 0); QEMU x86_64 microvm probes no PCID, so
//! `retaining()` is false. Both return `ok` without running. riscv64 runs it.
//! A rollover between the record and the shootdown (another task forking
//! through the last ASID) resets the table; the test then reports the miss.

use azos_arch::ARCH;
use azos_arch_api::{ArchPlatform, Cpu, Mmu};
use azos_arch_api::tlb_gen;
use azos_mm::pmm;

/// A user VA for the shootdown's range (nothing is mapped there).
const VA: usize = 0x20_0000_0000;

azos_ktest::ktest_late! {
    fn tlb_space_mask_reaches_the_harts_that_ran() {
        let n = azos_percpu::nr_cpu_ids();
        if !tlb_gen::SPACE_MASK || !azos_sched::asid::retaining() || n < 2 {
            return Ok(());
        }
        let frame = match pmm::alloc_page() {
            Ok(p) => p,
            Err(_) => return Err("no frame"),
        };
        let root = frame.as_usize();
        let word = ARCH.user_root_word(root, 1);
        let key = ARCH.tlb_space_key(word);
        if key == 0 {
            // Broadcast shootdown, no mask on this ISA.
            let _ = pmm::free_page(frame);
            return Ok(());
        }
        // The runner stays on one hart: `LAST_MARKED[me]` below is the record
        // of the shooter, which is the hart the runner is on.
        let _stay = azos_sync::preempt::critical_section();
        let me = ARCH.hart_id();
        let other = (me + 1) % n;
        tlb_gen::note_ran(key, other);
        let _ = ARCH.tlb_shootdown(root, VA, azos_arch::PAGE_SIZE);
        let marked = tlb_gen::LAST_MARKED[me].load(core::sync::atomic::Ordering::Relaxed);
        let ran = tlb_gen::SPACES.lookup(key, tlb_gen::SPACE_PROBE);
        let _ = pmm::free_page(frame);
        if ran != Some(1 << other) {
            return Err("the table does not name exactly the hart that ran the space");
        }
        if marked & (1 << other) == 0 {
            return Err("the shootdown did not mark the hart that ran the space");
        }
        Ok(())
    }
}
