// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest `asid_rollover_no_stale_translation` (N12, Kconfig `TLB_RETAIN`).
//!
//! Two address spaces A and B map the same VA to different frames and get
//! the SAME ASID in consecutive generations (a forced rollover between the
//! two allocations; with `ASID_BITS=1` every allocation is one). Task X runs
//! on A and reads the VA, which caches A's translation under that ASID;
//! then it yields straight to task Y on B (both pinned to one hart, so no
//! other ASID is installed in between). Y must read B's frame: the switch
//! sees a generation the hart has not flushed for and flushes.
//!
//! Canary (runtime): `canary=asid-rollover-noflush` skips that generation
//! flush, so Y reads A's frame through the stale entry: `not ok`. Under
//! QEMU it discriminates only where the emulated TLB keeps entries across
//! a root write with an unchanged tag (aarch64: yes, `TTBR0_EL1` writes
//! flush only on an ASID change); QEMU's x86_64 flushes on every CR3 write
//! and cannot show it.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_arch::{ArchPlatform, PagePerms};
use azos_mm::{addr, pmm, vmm};

const PRIO: u32 = 4;

/// Far from every mapping (the `tlb_probe` choice): riscv64 vpn2 = 128,
/// inside aarch64's 39-bit TTBR0 range; x86_64 PML4 slot 1.
#[cfg(not(target_arch = "x86_64"))]
const VA: usize = 0x20_0000_0000 + 0x10_0000;
#[cfg(target_arch = "x86_64")]
const VA: usize = 0x80_0000_0000 + 0x10_0000;

const A_VAL: u64 = 0xA11C_EA11_CEA1_1CE0;
const B_VAL: u64 = 0xB0B0_B0B0_B0B0_B0B0;

static STAGE: AtomicU32 = AtomicU32::new(0);
static Y_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);
static WA: AtomicUsize = AtomicUsize::new(0);
static ROOT_B: AtomicUsize = AtomicUsize::new(0);
static WB: AtomicUsize = AtomicUsize::new(0);
static RA: AtomicU64 = AtomicU64::new(0);
static RB: AtomicU64 = AtomicU64::new(0);
/// 0 ok; 1 X never ran on A; 2 Y never ran on B; 3 the two ASIDs differ;
/// 4 a read faulted.
static WHY: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
struct Load { value: u64, cause: u64 }

unsafe extern "C" {
    /// `tlb_probe.rs`'s fault-safe 8-byte load (cause 0 = no fault).
    fn azos_tlb_probe_load(va: usize) -> Load;
}

/// The root word this hart's translation register holds now, comparable with
/// a word from `asid::new_root_word` (x86_64: CR3 without the no-flush bit).
fn live_word() -> usize {
    #[cfg(target_arch = "riscv64")]
    { azos_arch::csr::read_satp() }
    #[cfg(target_arch = "aarch64")]
    { azos_arch::sysregs::read_ttbr0_el1() as usize }
    #[cfg(target_arch = "x86_64")]
    { azos_arch::mmu::cpu::read_cr3() as usize }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
    compile_error!("asid_rollover: no translation-root read for this ISA")
}

fn new_root(frame: usize) -> Option<usize> {
    let pt = vmm::create_pagetable().ok()?;
    if vmm::va_is_kernel_mapped(VA) || vmm::map(pt, VA, frame, PagePerms::KERNEL_RW).is_err() {
        return None;
    }
    vmm::copy_kernel_entries_to_user(pt);
    Some(pt)
}

fn fill(frame: usize, word: u64) {
    let p = addr::phys_to_virt(frame) as *mut u64;
    for i in 0..(azos_arch::PAGE_SIZE / 8) {
        unsafe { core::ptr::write_volatile(p.add(i), word) };
    }
    core::sync::atomic::fence(Ordering::SeqCst);
}

fn read(out: &AtomicU64) {
    let r = unsafe { azos_tlb_probe_load(VA) };
    if r.cause != 0 {
        WHY.store(4, Ordering::SeqCst);
    }
    out.store(r.value, Ordering::SeqCst);
}

/// Back on the kernel's own root before the roots are left behind.
fn leave() {
    azos_sched::set_current_user_info(azos_sched::kernel_task_satp(), 0, 0);
    azos_sched::task_yield();
}

fn task_x(_: usize) {
    while Y_IDX.load(Ordering::SeqCst) == usize::MAX {
        azos_sched::task_yield();
    }
    let wa = WA.load(Ordering::SeqCst);
    azos_sched::set_current_user_info(wa as u64, 0, 0);
    azos_sched::task_yield(); // the switch back in installs A
    if live_word() & !(1usize << 63) != wa {
        WHY.store(1, Ordering::SeqCst);
    }
    read(&RA); // A's translation is now cached under A's ASID
    // The rollover: B gets A's ASID in the next generation.
    azos_sched::asid::force_rollover_next();
    let b = ROOT_B.load(Ordering::SeqCst);
    let wb = azos_sched::asid::new_root_word(b);
    let arch = &azos_arch::ARCH;
    if arch.user_root_asid(wb) != arch.user_root_asid(wa) {
        WHY.store(3, Ordering::SeqCst);
    }
    WB.store(wb, Ordering::SeqCst);
    azos_sched::set_task_user_info(Y_IDX.load(Ordering::SeqCst), wb as u64, 0, 0);
    STAGE.store(1, Ordering::SeqCst);
    azos_sched::task_yield(); // straight to Y: A -> B, same ASID
    while STAGE.load(Ordering::SeqCst) < 2 {
        azos_sched::task_yield();
    }
    leave();
    STAGE.store(3, Ordering::SeqCst);
}

fn task_y(_: usize) {
    if let Some((idx, _)) = azos_sched::current_task_slot() {
        Y_IDX.store(idx, Ordering::SeqCst);
    }
    while STAGE.load(Ordering::SeqCst) < 1 {
        azos_sched::task_yield();
    }
    // Switched in on B (X set this task's word before yielding).
    if live_word() & !(1usize << 63) != WB.load(Ordering::SeqCst) {
        WHY.store(2, Ordering::SeqCst);
    }
    read(&RB);
    STAGE.store(2, Ordering::SeqCst);
    leave();
}

azos_ktest::ktest_late! {
    fn asid_rollover_no_stale_translation() {
        if !azos_sched::asid::retaining() {
            // TLB_RETAIN=n or no ASID bits: every switch flushes, nothing to test.
            return Ok(());
        }
        let (fa, fb) = match (pmm::alloc_page(), pmm::alloc_page()) {
            (Ok(p), Ok(q)) => (p.as_usize(), q.as_usize()),
            _ => return Err("no frame"),
        };
        fill(fa, A_VAL);
        fill(fb, B_VAL);
        let (Some(a), Some(b)) = (new_root(fa), new_root(fb)) else {
            return Err("could not build the two roots");
        };
        ROOT_B.store(b, Ordering::SeqCst);
        // A takes ASID 1 of a fresh generation; B will take it in the next.
        azos_sched::asid::force_rollover_next();
        WA.store(azos_sched::asid::new_root_word(a), Ordering::SeqCst);
        let hart = (azos_percpu::nr_cpu_ids() - 1) as i8;
        azos_sched::task_create_affinity("asid-y", task_y, 0, PRIO, hart);
        azos_sched::task_create_affinity("asid-x", task_x, 0, PRIO, hart);
        crate::ktest::wait("the two tasks never finished", || STAGE.load(Ordering::SeqCst) >= 3)?;
        // The roots and frames stay allocated: two pages each, once per boot.
        match WHY.load(Ordering::SeqCst) {
            0 => {}
            1 => return Err("X never ran on A"),
            2 => return Err("Y never ran on B"),
            3 => return Err("A and B did not share an ASID"),
            _ => return Err("a probe read faulted"),
        }
        if RA.load(Ordering::SeqCst) != A_VAL {
            return Err("X read the wrong frame through A");
        }
        match RB.load(Ordering::SeqCst) {
            B_VAL => Ok(()),
            A_VAL => Err("stale translation: B read A's frame after the ASID rollover"),
            _ => Err("Y read neither frame"),
        }
    }
}
