// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cost lanes of the EL1/EL2 split (feature `hyp-cost-probe`, a bench and gate
//! hook, never in a real build). Each lane is timed twice in one boot, once
//! before the image lock and once after the last lock: the code path is the
//! same, so what changes between the two numbers is what the monitor puts on it.
//! In a hosted image nothing is locked, so the two numbers are the same path
//! twice: the control that shows how much a lane moves by itself.
//!
//! The lines are read by `tools/bench/hyp_cost.py`:
//! `[HYP] cost: <lane>: <ops> ops, <before> ticks before, <after> ticks after`.
//! A lane that does not apply to the image says so and prints no number.

use core::sync::atomic::{AtomicU64, Ordering};

use azos_drv_sys::{kprintln, timebase};

/// Operations per lane per stage.
const OPS: u64 = 256;
const WARMUP: u64 = 8;

#[repr(C, align(4096))]
struct Page([u8; 4096]);
static mut SCRATCH: Page = Page([0; 4096]);

const LANES: usize = 5;
const NAMES: [&str; LANES] = ["hvc-null", "psci-version", "pt-map-unmap", "pt-set", "text-patch"];
/// Ticks of each lane before the lock; `u64::MAX` when the lane did not run.
static BEFORE: [AtomicU64; LANES] = [const { AtomicU64::new(u64::MAX) }; LANES];
static TTBR0_BEFORE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Who answers an `HVC` from this kernel: `split` (the resident monitor,
/// `CALL_PROBE`), `hosted` (the stub, `HVC_PROBE`) or `none` (no EL2).
fn hvc_op() -> (&'static str, Option<fn()>) {
    #[cfg(feature = "hyp-monitor")]
    if super::hyp_monitor::null_call() {
        return ("split", Some(|| { super::hyp_monitor::null_call(); }));
    }
    #[cfg(feature = "hv")]
    if azos_arch::ext::hv::probe().is_some() {
        return ("hosted", Some(|| { azos_arch::ext::hv::probe(); }));
    }
    ("none", None)
}

fn mode() -> &'static str {
    hvc_op().0
}

fn timed(mut op: impl FnMut()) -> u64 {
    for _ in 0..WARMUP {
        op();
    }
    let t0 = timebase::now();
    for _ in 0..OPS {
        op();
    }
    timebase::now() - t0
}

/// One lane's ticks now, `None` when it does not apply to this image or
/// the call failed. `locked`: the pool is the monitor's.
fn lane(i: usize, locked: bool) -> Option<u64> {
    match i {
        0 => hvc_op().1.map(timed),
        1 => Some(timed(|| {
            core::hint::black_box(azos_arch::firmware::features(azos_arch::firmware::PSCI_VERSION));
        })),
        2 => {
            let kpt = azos_mm::vmm::kernel_pagetable();
            let va = azos_mm::kstack::first_guard() & !(azos_arch::PAGE_SIZE - 1);
            let pa = azos_mm::addr::virt_to_phys(core::ptr::addr_of!(SCRATCH) as usize);
            let mut failed = false;
            let ticks = timed(|| {
                failed |= azos_mm::vmm::map(kpt, va, pa, azos_arch_api::PagePerms::KERNEL_RW).is_err();
                azos_mm::vmm::unmap_kernel(kpt, va);
            });
            (!failed).then_some(ticks)
        }
        3 => pt_set_lane(locked),
        _ => {
            if !azos_trace::STATIC_KEYS {
                return None;
            }
            let prev = azos_ipc::trace::set_mask(azos_trace::mask());
            let ticks = timed(|| { azos_ipc::trace::set_mask(azos_trace::mask() ^ 1); });
            // An odd number of flips ran: put the mask back.
            azos_ipc::trace::set_mask(prev);
            Some(ticks)
        }
    }
}

/// Write and clear a free slot of the kernel root: through the monitor once
/// the pool is its, with a plain store before.
fn pt_set_lane(locked: bool) -> Option<u64> {
    use azos_arch::mmu::pte_fmt::{AF, PXN, UXN};
    let root = azos_mm::vmm::kernel_pagetable();
    let slot_at = |i: usize| azos_mm::addr::phys_to_virt(root + i * 8) as *mut u64;
    // SAFETY: the root is mapped through the direct map; the read is of a table word.
    let free = (0..512).find(|&i| unsafe { core::ptr::read_volatile(slot_at(i)) } == 0)?;
    // A 1 GiB block of memory the kernel does not use, valid and inner-shareable, never executable.
    let word = 1u64 << 32 | 1 | AF | 0b11 << 8 | 1 << 2 | PXN | UXN;
    let failed = core::cell::Cell::new(false);
    let ticks = timed(|| {
        #[cfg(feature = "hyp-monitor")]
        if locked {
            let entry = root + free * 8;
            failed.set(failed.get() | super::hyp_monitor::pt_set(entry, 0, word, 2).is_err());
            failed.set(failed.get() | super::hyp_monitor::pt_set(entry, word, 0, 2).is_err());
            return;
        }
        // SAFETY: a free slot of the root, before the pool is the monitor's (or in an image with no monitor).
        unsafe {
            core::ptr::write_volatile(slot_at(free), word);
            core::ptr::write_volatile(slot_at(free), 0);
        }
    });
    let _ = locked;
    (!failed.get()).then_some(ticks)
}

/// `PIN_COST` writes of this PE's `TTBR0_EL1` with the value it holds, each
/// with a local TLB flush, as an address-space switch does.
fn ttbr0_ticks() -> u64 {
    let root = azos_arch::sysregs::read_ttbr0_el1() as usize;
    timed(|| azos_arch::sysregs::install_ttbr0_flush_local(root))
}

/// Before the image lock.
pub(crate) fn before_lock() {
    for i in 0..LANES {
        if let Some(t) = lane(i, false) {
            BEFORE[i].store(t, Ordering::Relaxed);
        }
    }
    TTBR0_BEFORE.store(ttbr0_ticks(), Ordering::Relaxed);
}

/// After the last lock: measure again and print every lane.
pub(crate) fn after_lock() {
    let mode = mode();
    kprintln!("[HYP] cost: mode {}", mode);
    kprintln!("[HYP] cost: timebase {} Hz", timebase::freq());
    for i in 0..LANES {
        let before = BEFORE[i].load(Ordering::Relaxed);
        match (before != u64::MAX).then(|| lane(i, mode == "split")).flatten() {
            Some(after) => kprintln!("[HYP] cost: {}: {} ops, {} ticks before, {} ticks after", NAMES[i], OPS, before, after),
            None => kprintln!("[HYP] cost: {}: no number", NAMES[i]),
        }
    }
    kprintln!("[HYP] cost: ttbr0-write: {} ops, {} ticks before, {} ticks after", OPS, TTBR0_BEFORE.load(Ordering::Relaxed), ttbr0_ticks());
    kprintln!("[HYP] cost: done");
}

/// Ticks from the `CPU_ON` of the secondaries to the first one's own
/// publish of online: the monitor's entry substitution and per-PE init, plus
/// the kernel's secondary bring-up that is the same in both images.
pub(crate) fn cpu_on_online(ticks: u64) {
    kprintln!("[HYP] cost: cpu-on-online: 1 ops, {} ticks", ticks);
}
