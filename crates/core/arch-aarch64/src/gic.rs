// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! GICv3 — ARM Generic Interrupt Controller v3.
//!
//! Programs the distributor (GICD), the calling CPU's
//! redistributor (GICR), and the CPU interface (ICC_*
//! system registers). Sufficient to take interrupts via
//! `ICC_IAR1_EL1` and acknowledge them via `ICC_EOIR1_EL1`;
//! actual exception handling (vector table, SP/saved-state)
//! is a separate follow-up.
//!
//! # Address layout (QEMU virt + similar Arm reference designs)
//!
//! ```text
//! 0x0800_0000 ─ GICD (distributor)          ─ 64 KiB
//! 0x080A_0000 ─ GICR  (redistributor frames) ─ 128 KiB × NUM_CPUS
//! ```
//!
//! Real silicon (e.g. NXP S32G3, Ampere Altra) varies. This module does
//! NOT parse the device tree for these bases (audit finding): `init_
//! distributor()` takes no base argument, and `GICD_BASE`/`GICR_BASE`
//! below are the only values ever used — compile-time QEMU-virt
//! constants. `crates/drivers/dtb` parses `/cpus` for topology, not the GIC's own
//! MMIO windows; a third board with different GIC bases needs a new
//! constant here, not a DTB read.

// ──────────────────────────────────────────────────────────────────────────
// MMIO bases (QEMU virt)
// ──────────────────────────────────────────────────────────────────────────

/// GIC distributor base for `qemu-system-aarch64 -M virt`.
pub const GICD_BASE: usize = 0x0800_0000;

/// GIC redistributor base for `qemu-system-aarch64 -M virt`.
/// Each PE occupies a 128 KiB stride from this base.
pub const GICR_BASE: usize = 0x080A_0000;

/// Stride (in bytes) between consecutive PE redistributor frames.
/// GICv3 packs RD_base (64 KiB) + SGI_base (64 KiB).
pub const GICR_STRIDE: usize = 0x2_0000;

/// Bounded poll count for the GICR_WAKER ChildrenAsleep wait.
/// Real silicon clears within a handful of cycles; QEMU virt
/// may not model the bit at all (see `init_redistributor`).
pub const GICR_WAKE_MAX_SPINS: u32 = 1_000_000;

// ──────────────────────────────────────────────────────────────────────────
// Distributor register offsets (GIC Architecture Specification, §12)
// ──────────────────────────────────────────────────────────────────────────

const GICD_CTLR:       usize = 0x0000;
const GICD_TYPER:      usize = 0x0004;
const GICD_IGROUPR0:   usize = 0x0080;
const GICD_ISENABLER0: usize = 0x0100;
const GICD_ICENABLER0: usize = 0x0180;
const GICD_IPRIORITYR0:usize = 0x0400;

/// GICD_CTLR.EnableGrp1NS — bit 1 (non-secure access).
const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;
/// GICD_CTLR.ARE_NS — Affinity Routing Enable, non-secure (bit 4).
/// Mandatory for GICv3 to use the ICC_* system-register interface.
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
/// GICD_CTLR.RWP — Register Write Pending (read-only).
const GICD_CTLR_RWP: u32 = 1 << 31;

// ──────────────────────────────────────────────────────────────────────────
// Redistributor register offsets
// ──────────────────────────────────────────────────────────────────────────

/// Within RD_base (first 64 KiB of a PE's frame).
const GICR_CTLR:  usize = 0x0000;
const GICR_WAKER: usize = 0x0014;

/// GICR_WAKER.ProcessorSleep — bit 1.
const GICR_WAKER_PROCESSOR_SLEEP:  u32 = 1 << 1;
/// GICR_WAKER.ChildrenAsleep — bit 2 (read-only, mirrors above).
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

// SGI_base (second 64 KiB) holds PPI/SGI registers — offsets are
// added on top of `RD_base + 0x10000`.
const GICR_SGI_OFFSET:        usize = 0x1_0000;
const GICR_IGROUPR0:          usize = 0x0080;
const GICR_ISENABLER0:        usize = 0x0100;
const GICR_ICENABLER0:        usize = 0x0180;
const GICR_IPRIORITYR0:       usize = 0x0400;

/// `GICR_TYPER` — 64-bit, within `RD_base` (§12.11). Carries this frame's
/// PE affinity (for frame discovery) and topology flags (`Last`, `VLPIS`).
const GICR_TYPER: usize = 0x0008;
/// `GICR_TYPER.Last` (bit 4) — set on the final redistributor frame of a
/// contiguous series. A walk must stop here even short of its own cap.
const GICR_TYPER_LAST: u64 = 1 << 4;
/// `GICR_TYPER.VLPIS` (bit 1) — this frame implements virtual LPIs, which
/// doubles it from 2×64 KiB (RD_base + SGI_base) to 4×64 KiB (+ VLPI_base
/// + reserved). Not exercised by QEMU virt today, but a walk that assumed
/// every frame is `GICR_STRIDE` apart would silently misparse a system
/// that mixes VLPI-capable and plain redistributors — reading each
/// frame's own stride from its own TYPER avoids that regardless.
const GICR_TYPER_VLPIS: u64 = 1 << 1;

// ──────────────────────────────────────────────────────────────────────────
// Pure decode/encode — no `target_arch` gate, no `core::arch::asm!`.
//
// Deliberately free of ANY hardware access so they can be exercised from
// the host test suite (`tests/host/arch-api-tests`) exactly as written. That
// matters on more than one platform: this project is developed on Apple
// Silicon, where `cargo test`'s host target is `aarch64-apple-darwin` —
// `target_arch = "aarch64"` is TRUE there, so a function gated on that
// alone would still compile its real-hardware body (see
// `arch-aarch64::features`'s header comment for the exact bug this
// project already hit that way: an EL1-only sysreg read that is an
// illegal instruction at EL0 under macOS). Everything below only ever
// touches integers, so there is nothing to gate.
// ──────────────────────────────────────────────────────────────────────────

/// Pack a raw `GICR_TYPER` value's affinity fields into the same `u32`
/// shape [`crate::mpidr::affinity_key`] uses: `Aff3<<24 | Aff2<<16 |
/// Aff1<<8 | Aff0`. TYPER carries them at `Aff0=[39:32]`, `Aff1=[47:40]`,
/// `Aff2=[55:48]`, `Aff3=[63:56]` — the same four bytes MPIDR carries,
/// just shifted up by 32 bits and with Aff1/Aff2 swapped relative to
/// MPIDR's own layout, which is exactly the kind of transposition a
/// canary must catch rather than a reader eyeballing the shifts.
pub const fn typer_affinity_key(typer: u64) -> u32 {
    (((typer >> 32) & 0xFF) as u32)
        | ((((typer >> 40) & 0xFF) as u32) << 8)
        | ((((typer >> 48) & 0xFF) as u32) << 16)
        | ((((typer >> 56) & 0xFF) as u32) << 24)
}

/// `GICR_TYPER.Last` (bit 4).
pub const fn typer_is_last(typer: u64) -> bool {
    typer & GICR_TYPER_LAST != 0
}

/// Byte stride from this frame's `RD_base` to the NEXT frame's `RD_base`,
/// read from THIS frame's own `TYPER.VLPIS` rather than assumed uniform.
pub const fn typer_frame_stride(typer: u64) -> usize {
    if typer & GICR_TYPER_VLPIS != 0 {
        GICR_STRIDE * 2
    } else {
        GICR_STRIDE
    }
}

/// Encode an `ICC_SGI1R_EL1` value targeting the PE whose affinity is
/// `target_affinity` (packed via [`crate::mpidr::affinity_key`] /
/// [`typer_affinity_key`]), for SGI `intid` (0..=15, masked if wider).
///
/// Bit layout (GIC architecture spec, `ICC_SGI1R_EL1`):
///   \[15:0\]  TargetList — bit N = the PE whose Aff0 low nibble is N
///   \[23:16\] Aff1
///   \[27:24\] INTID
///   \[39:32\] Aff2
///   \[40\]    IRM (0 = TargetList/Aff*, 1 = all-but-self — always 0 here)
///   \[47:44\] RS  — Range Selector: `TargetList` bit N really means
///             `Aff0 == RS*16 + N`, i.e. WHICH group of 16 Aff0 values
///             the list addresses.
///   \[55:48\] Aff3
///
/// **Why this exists alongside [`crate::mpidr::Mpidr::sgi_to_self_aff0`]:**
/// that method omits `RS` — harmless while every caller's Aff0 is < 16 (16
/// bits of TargetList cover QEMU virt's `-smp 2..4` outright), wrong the
/// moment a topology puts a target PE at Aff0 >= 16. This is the general
/// form the redistributor-walk-based SMP path uses.
pub const fn sgi1r_encode(target_affinity: u32, intid: u8) -> u64 {
    let aff0 = (target_affinity & 0xFF) as u64;
    let aff1 = ((target_affinity >> 8) & 0xFF) as u64;
    let aff2 = ((target_affinity >> 16) & 0xFF) as u64;
    let aff3 = ((target_affinity >> 24) & 0xFF) as u64;
    let target_list: u64 = 1u64 << (aff0 & 0xF);
    let rs: u64 = aff0 >> 4;
    target_list
        | (aff1 << 16)
        | ((intid as u64 & 0xF) << 24)
        | (aff2 << 32)
        | (rs << 44)
        | (aff3 << 48)
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn mmio_read32(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn mmio_write32(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

/// Wait for any pending distributor register write to complete.
/// Reading GICD_CTLR.RWP clears once the in-flight write is
/// visible to all PEs.
#[cfg(target_arch = "aarch64")]
fn gicd_wait_rwp() {
    unsafe {
        while mmio_read32(GICD_BASE + GICD_CTLR) & GICD_CTLR_RWP != 0 {
            core::hint::spin_loop();
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Init sequence
// ──────────────────────────────────────────────────────────────────────────

/// Initialise the distributor. Must be called once during boot,
/// before any redistributor / CPU-interface init.
#[cfg(target_arch = "aarch64")]
pub fn init_distributor() {
    unsafe {
        // 1. Disable distributor while we configure it.
        mmio_write32(GICD_BASE + GICD_CTLR, 0);
        gicd_wait_rwp();

        // 2. Discover number of SPIs from GICD_TYPER.ITLinesNumber
        //    (bits [4:0]). N → 32 * (N + 1) interrupt IDs total
        //    (including SGIs/PPIs).
        let typer = mmio_read32(GICD_BASE + GICD_TYPER);
        let it_lines = (typer & 0x1F) as usize;
        // The INTIDs this distributor implements, for the ring-3 bind's
        // refusal of a line past them (wave 10 IRQ5).
        note_spi_limit(typer);

        // 3. For each SPI (INTID >= 32): default group 1 (NS),
        //    priority 0xA0, disabled.
        for i in 1..=it_lines {
            let off = i * 4;
            mmio_write32(GICD_BASE + GICD_IGROUPR0 + off, 0xFFFF_FFFF);
            mmio_write32(GICD_BASE + GICD_ICENABLER0 + off, 0xFFFF_FFFF);
        }
        // 4. Default priority for SPI lines (4 bytes per INTID).
        for i in 8..(8 + it_lines * 8) {
            mmio_write32(GICD_BASE + GICD_IPRIORITYR0 + i * 4, 0xA0A0_A0A0);
        }

        // 5. Enable distributor, Group 1 NS, Affinity Routing.
        mmio_write32(
            GICD_BASE + GICD_CTLR,
            GICD_CTLR_ENABLE_GRP1_NS | GICD_CTLR_ARE_NS,
        );
        gicd_wait_rwp();
    }
}

/// Initialise the calling PE's redistributor. Pass the CPU's
/// affinity index (0..NUM_HARTS); the function picks the right
/// 128 KiB frame.
///
/// **Assumes index == frame slot**, which QEMU virt's flat, single-cluster
/// `-smp N` topology happens to satisfy (frame `i` is always the PE with
/// `Aff0=i, Aff1=Aff2=Aff3=0`) but real silicon is not required to. Kept
/// exactly as-is — existing callers (`kernel/src/main.rs`,
/// `aarch64-smoke`) pass hart index and rely on this. New SMP bring-up
/// code that cannot assume the topology should call [`find_redistributor`]
/// (matches `GICR_TYPER`'s own affinity against an MPIDR) and
/// [`init_redistributor_at`] instead — this function is now a thin
/// wrapper over that pair for the index-known case.
#[cfg(target_arch = "aarch64")]
pub fn init_redistributor(cpu_id: usize) {
    init_redistributor_at(GICR_BASE + cpu_id * GICR_STRIDE);
}

/// Initialise the redistributor frame whose `RD_base` is `rd_base` —
/// the address-based primitive [`init_redistributor`] (index-based) and
/// the affinity-walk SMP path both funnel through.
///
/// The wake-up sequence (GICR_WAKER) is GICv3-mandated — without
/// it the per-CPU SGI/PPI lines stay masked.
#[cfg(target_arch = "aarch64")]
pub fn init_redistributor_at(rd_base: usize) {
    let sgi_base = rd_base + GICR_SGI_OFFSET;

    unsafe {
        // 1. Clear ProcessorSleep, wait ChildrenAsleep == 0.
        //
        // Bounded by `GICR_WAKE_MAX_SPINS` because some
        // simulations (QEMU virt at the time of writing)
        // don't model the wake-up handshake — they boot the
        // PE awake and ChildrenAsleep is stuck at 0 or stuck
        // at 1 depending on implementation. An infinite wait
        // would wedge boot.
        let mut waker = mmio_read32(rd_base + GICR_WAKER);
        waker &= !GICR_WAKER_PROCESSOR_SLEEP;
        mmio_write32(rd_base + GICR_WAKER, waker);
        let mut spins = 0u32;
        while mmio_read32(rd_base + GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP != 0
            && spins < GICR_WAKE_MAX_SPINS
        {
            core::hint::spin_loop();
            spins += 1;
        }

        // 2. PPI/SGI defaults: group 1 NS, disabled, priority 0xA0.
        mmio_write32(sgi_base + GICR_IGROUPR0, 0xFFFF_FFFF);
        mmio_write32(sgi_base + GICR_ICENABLER0, 0xFFFF_FFFF);
        for i in 0..8 {
            mmio_write32(
                sgi_base + GICR_IPRIORITYR0 + i * 4,
                0xA0A0_A0A0,
            );
        }
        // GICR_CTLR — leave at reset (we don't use LPIs).
        let _ = mmio_read32(rd_base + GICR_CTLR);
    }
}

/// Initialise the per-CPU interface via ICC system registers.
/// Must run AFTER `init_redistributor` for the calling PE.
#[cfg(target_arch = "aarch64")]
pub fn init_cpu_interface() {
    unsafe {
        // ICC_SRE_EL1.SRE = 1 — use the system-register interface
        // (the MMIO cpu interface, GICC_*, isn't even mapped in
        // GICv3 by default).
        let mut sre: u64;
        core::arch::asm!(
            "mrs {0}, ICC_SRE_EL1",
            out(reg) sre,
            options(nomem, nostack, preserves_flags),
        );
        sre |= 1;
        core::arch::asm!(
            "msr ICC_SRE_EL1, {0}",
            "isb",
            in(reg) sre,
            options(nomem, nostack, preserves_flags),
        );

        // ICC_PMR_EL1 = 0xFF — accept any priority.
        core::arch::asm!(
            "msr ICC_PMR_EL1, {0}",
            in(reg) 0xFFu64,
            options(nomem, nostack, preserves_flags),
        );

        // ICC_BPR1_EL1 = 0 — no preemption-priority grouping.
        core::arch::asm!(
            "msr ICC_BPR1_EL1, {0}",
            in(reg) 0u64,
            options(nomem, nostack, preserves_flags),
        );

        // ICC_IGRPEN1_EL1.Enable = 1 — enable Group 1 NS.
        core::arch::asm!(
            "msr ICC_IGRPEN1_EL1, {0}",
            "isb",
            in(reg) 1u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Per-interrupt control (SPIs only — PPIs/SGIs use redistributor)
// ──────────────────────────────────────────────────────────────────────────

/// Enable SPI `intid` (must be ≥ 32). PPI/SGI use the
/// per-PE redistributor SGI_base register and need a separate
/// helper once we wire those.
#[cfg(target_arch = "aarch64")]
pub fn enable_spi(intid: u32) {
    debug_assert!(intid >= 32, "use enable_ppi for INTIDs below 32");
    let reg = (intid / 32) as usize * 4;
    let bit = 1u32 << (intid % 32);
    unsafe {
        mmio_write32(GICD_BASE + GICD_ISENABLER0 + reg, bit);
        gicd_wait_rwp();
    }
}

/// `GICD_ICFGR<n>`: 2 bits per INTID, 16 INTIDs per register (§12.9.9).
const GICD_ICFGR0: usize = 0x0C00;
/// `GICD_IROUTER<n>`: one 64-bit register per SPI, at `0x6000 + 8 * n`
/// (§12.9.22). Only meaningful with `GICD_CTLR.ARE_NS = 1`, which
/// [`init_distributor`] sets.
const GICD_IROUTER0: usize = 0x6000;

/// `GICD_IROUTER` value that targets exactly the PE whose `MPIDR_EL1` is
/// `mpidr`: Aff3 at [39:32], Aff2/Aff1/Aff0 at [23:0], `Interrupt_Routing_
/// Mode` (bit 31) clear — "this PE", not "any participating PE". The same
/// field layout as MPIDR itself, minus MPIDR's bits 24 (MT), 30 (U) and 31
/// (RES1), which are not affinity.
pub const fn irouter_for_mpidr(mpidr: u64) -> u64 {
    mpidr & 0xFF_00FF_FFFF
}

/// `GICD_ICFGR<intid / 16>` with INTID `intid`'s trigger field rewritten:
/// the upper bit of its 2-bit field is 1 for edge, 0 for level (§12.9.9);
/// the lower bit is RES0 for SPIs. Other INTIDs' fields are kept.
pub const fn icfgr_with_trigger(old: u32, intid: u32, edge: bool) -> u32 {
    let bit = 1u32 << (((intid % 16) * 2) + 1);
    if edge { old | bit } else { old & !bit }
}

/// Route SPI `intid` to the PE `mpidr` names and set its trigger, then
/// enable it. Must run after [`init_distributor`] (which leaves every SPI
/// disabled, Group 1 NS, priority 0xA0), and the caller must be ready to
/// take the interrupt: a level line whose device is already asserting
/// fires as soon as this returns and the PE unmasks IRQs.
///
/// `GICD_IROUTER`'s reset value is architecturally UNKNOWN; QEMU happens to
/// reset it to affinity 0.0.0.0, which is why never writing it would have
/// looked fine there.
///
/// A line routed here is the kernel's: [`user_spi_bind`] refuses it from then
/// on, so a `Cap<Irq>` naming the console line cannot mask it.
#[cfg(target_arch = "aarch64")]
pub fn route_spi(intid: u32, mpidr: u64, edge: bool) {
    debug_assert!((32..1020).contains(&intid), "route_spi takes an SPI INTID");
    spi_set(&KERNEL_SPI, intid);
    route_spi_raw(intid, mpidr, edge);
}

/// ICFGR/IROUTER write + enable, shared by the kernel's and ring 3's route.
/// `ICFGR` is a read-modify-write of a register sixteen INTIDs share; a bind
/// can run on any PE at any time, so the RMW is serialised by [`ROUTE_LOCK`],
/// held with IRQs masked (DAIF.I) so a holder is never preempted while a
/// same-hart task spins on it.
#[cfg(target_arch = "aarch64")]
fn route_spi_raw(intid: u32, mpidr: u64, edge: bool) {
    let cfg_reg = GICD_BASE + GICD_ICFGR0 + (intid / 16) as usize * 4;
    let daif: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, DAIF",
            "msr DAIFSet, #2",
            out(reg) daif,
            options(nostack, preserves_flags),
        );
    }
    while ROUTE_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    unsafe {
        let old = mmio_read32(cfg_reg);
        mmio_write32(cfg_reg, icfgr_with_trigger(old, intid, edge));
        mmio_write64(GICD_BASE + GICD_IROUTER0 + intid as usize * 8, irouter_for_mpidr(mpidr));
        gicd_wait_rwp();
    }
    ROUTE_LOCK.store(false, Ordering::Release);
    unsafe {
        // Not `nomem`: a compiler barrier, so the release store above stays
        // inside the masked window.
        core::arch::asm!("msr DAIF, {0}", in(reg) daif, options(nostack, preserves_flags));
    }
    enable_spi(intid);
}

/// Disable (mask) SPI `intid` at the distributor and wait until the disable
/// has taken effect (`GICD_CTLR.RWP` covers `GICD_ICENABLER` writes, §12.9.4):
/// once this returns the line cannot be signalled to any PE again until
/// [`enable_spi`], whatever the device does.
#[cfg(target_arch = "aarch64")]
pub fn disable_spi(intid: u32) {
    let reg = (intid / 32) as usize * 4;
    let bit = 1u32 << (intid % 32);
    unsafe {
        mmio_write32(GICD_BASE + GICD_ICENABLER0 + reg, bit);
        gicd_wait_rwp();
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Ring-3 SPI ownership (`SYS_IRQ_BIND` / `SYS_PORT_BIND_TYPED`, ACK 305)
//
// A line a ring-3 driver bound is delivered mask-until-ACK: `handle_irq`
// masks it (`GICD_ICENABLER`), EOIs it, then queues/wakes; the driver's
// `SYS_DRV_IRQ_ACK` unmasks it (`GICD_ISENABLER`). Two bitmaps, one bit per
// INTID 0..1023: lines the kernel routed for itself, and lines ring 3 bound.
// Plain atomics, no lock: `handle_irq` reads `USER_SPI` on every SPI.
// ──────────────────────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Lines the kernel routed for itself ([`route_spi`]).
static KERNEL_SPI: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
/// Lines a ring-3 driver bound ([`user_spi_bind`]). Cleared when the line's
/// last binding goes at task exit ([`user_spi_release`], through
/// `irq_bind`'s release hook), which masks the line first.
static USER_SPI: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
/// SPIs whose trigger the device tree gives ([`note_dtb_trigger`]), and of
/// those, the edge-triggered ones. Written once at boot, before any bind.
static DTB_DESCRIBED: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
static DTB_EDGE: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
/// Serialises the `GICD_ICFGR` read-modify-write in `route_spi_raw`.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
static ROUTE_LOCK: AtomicBool = AtomicBool::new(false);

/// Whether `intid` is a line ring 3 may bind at all: an SPI (32..=1019).
/// SGIs/PPIs are per-PE (the kernel's IPI and timer), 1020..1023 are special
/// INTIDs, and LPIs are ITS-routed with no distributor enable bit.
pub const fn user_spi_in_range(intid: u32) -> bool {
    intid >= 32 && intid < 1020
}

fn spi_set(map: &[AtomicU32; 32], intid: u32) {
    if let Some(w) = map.get((intid / 32) as usize) {
        w.fetch_or(1 << (intid % 32), Ordering::AcqRel);
    }
}

fn spi_clear(map: &[AtomicU32; 32], intid: u32) {
    if let Some(w) = map.get((intid / 32) as usize) {
        w.fetch_and(!(1 << (intid % 32)), Ordering::AcqRel);
    }
}

fn spi_test(map: &[AtomicU32; 32], intid: u32) -> bool {
    match map.get((intid / 32) as usize) {
        Some(w) => w.load(Ordering::Acquire) & (1 << (intid % 32)) != 0,
        None => false,
    }
}

/// Record the trigger the device tree gives SPI `intid` (boot, from
/// `azos_dtb::dtb_irq_triggers`): [`user_spi_bind`] programs it.
pub fn note_dtb_trigger(intid: u32, edge: bool) {
    if !user_spi_in_range(intid) {
        return;
    }
    spi_set(&DTB_DESCRIBED, intid);
    if edge {
        spi_set(&DTB_EDGE, intid);
    } else {
        spi_clear(&DTB_EDGE, intid);
    }
}

/// The trigger the device tree gave `intid`: `Some(true)` edge, `Some(false)`
/// level, `None` when it described no such SPI.
pub fn dtb_trigger(intid: u32) -> Option<bool> {
    if spi_test(&DTB_DESCRIBED, intid) {
        Some(spi_test(&DTB_EDGE, intid))
    } else {
        None
    }
}

/// One past the largest INTID the distributor implements:
/// `32 * (GICD_TYPER.ITLinesNumber + 1)`, capped at 1020 ([`note_spi_limit`],
/// from `init_distributor`). 1020 until then. An SPI at or past it has
/// RAZ/WI enable, route and configuration registers: a bind of it would
/// answer 0 with a line nothing can deliver.
static SPI_LIMIT: AtomicU32 = AtomicU32::new(1020);

/// Record [`SPI_LIMIT`] from a `GICD_TYPER` value.
pub fn note_spi_limit(typer: u32) {
    let lines = 32 * ((typer & 0x1F) + 1);
    SPI_LIMIT.store(lines.min(1020), Ordering::Relaxed);
}

/// Whether the distributor implements SPI `intid` ([`SPI_LIMIT`]).
pub fn user_spi_implemented(intid: u32) -> bool {
    user_spi_in_range(intid) && intid < SPI_LIMIT.load(Ordering::Relaxed)
}

/// Whether ring 3 may take `intid`: an SPI the kernel did not route itself.
pub fn user_spi_bindable(intid: u32) -> bool {
    user_spi_in_range(intid) && !spi_test(&KERNEL_SPI, intid)
}

/// Whether a ring-3 driver bound `intid` (the `handle_irq` test).
#[inline]
pub fn user_spi_owned(intid: u32) -> bool {
    user_spi_in_range(intid) && spi_test(&USER_SPI, intid)
}

/// Record `intid` as ring-3 owned without touching the GIC. Host tests only
/// reach the bitmap through this; the kernel goes through [`user_spi_bind`].
pub fn user_spi_mark(intid: u32) -> bool {
    if !user_spi_bindable(intid) {
        return false;
    }
    spi_set(&USER_SPI, intid);
    true
}

/// Forget ring-3 ownership of `intid` without touching the GIC. Host tests
/// only reach the bitmap through this; the kernel goes through
/// [`user_spi_release`]. `false` when the line was not ring-3 owned.
pub fn user_spi_unmark(intid: u32) -> bool {
    if !user_spi_owned(intid) {
        return false;
    }
    spi_clear(&USER_SPI, intid);
    true
}

/// Hand `intid` back from ring 3 when its last binding went (task exit,
/// `irq_bind::irq_unbind_all` → the release hook): mask it at the
/// distributor, then forget the ownership. Mask first: `handle_irq` on
/// another PE that still sees the line owned masks it again (harmless); one
/// that already sees it unowned finds it masked, so it cannot be taken again
/// unmasked with nobody left to ACK. A line not ring-3 owned is left alone.
#[cfg(target_arch = "aarch64")]
pub fn user_spi_release(intid: u32) {
    if !user_spi_owned(intid) {
        return;
    }
    disable_spi(intid);
    let _ = user_spi_unmark(intid);
}

/// Take `intid` for ring 3: mark it owned, route it to the PE `mpidr` names
/// with the trigger the device tree gave it ([`dtb_trigger`]; level when the
/// tree does not describe the line), and enable it. `false` (nothing written) for a line outside
/// the SPI range, one the kernel routed for itself, or one past the SPIs the
/// distributor implements ([`user_spi_implemented`]; the syscall then answers
/// `-ENODEV` and drops its binding — wave 10 IRQ5). Enables on every call:
/// a bind is "ready to receive", so a line left masked by a driver that died
/// before its ACK is live again for the next one.
///
/// Mask-until-ACK is sound for both triggers: a masked (disabled) SPI still
/// latches its pending state at the distributor, so an edge that arrives
/// while ring 3 has not ACKed is forwarded by the ACK's enable, not lost.
/// QEMU `virt`'s PL031 (`<0 2 4>`) is level; its virtio-mmio SPIs are edge.
#[cfg(target_arch = "aarch64")]
pub fn user_spi_bind(intid: u32, mpidr: u64) -> bool {
    if !user_spi_implemented(intid) || !user_spi_mark(intid) {
        return false;
    }
    route_spi_raw(intid, mpidr, dtb_trigger(intid).unwrap_or(false));
    true
}

/// Read back what [`route_spi`] wrote, for the boot line that proves it:
/// `(GICD_IROUTER<intid>, edge, enabled)`.
#[cfg(target_arch = "aarch64")]
pub fn spi_state(intid: u32) -> (u64, bool, bool) {
    unsafe {
        let router = core::ptr::read_volatile(
            (GICD_BASE + GICD_IROUTER0 + intid as usize * 8) as *const u64);
        let cfg = mmio_read32(GICD_BASE + GICD_ICFGR0 + (intid / 16) as usize * 4);
        let en = mmio_read32(GICD_BASE + GICD_ISENABLER0 + (intid / 32) as usize * 4);
        (router, cfg & (1 << (((intid % 16) * 2) + 1)) != 0, en & (1 << (intid % 32)) != 0)
    }
}

/// The EL1 VIRTUAL timer's PPI (`CNTV_*`) — the kernel's tick and one-shot
/// deadline line, on every core (GICv3 PPI 11, INTID 27; Linux's
/// `ARCH_TIMER_VIRT_PPI`). The kernel programs `CNTV_CVAL_EL0`/`CNTV_CTL_EL0`
/// and reads `CNTVCT_EL0`, never the physical timer, so this and nothing else
/// is the line to enable and to dispatch on.
pub const PPI_VIRT_TIMER: u32 = 27;

/// The EL1 PHYSICAL timer's PPI (INTID 30). No longer the kernel's tick; kept
/// as a name so the one-clock canary (`a64clk-ppi-canary`: enable this line
/// while `CNTV_*` is programmed) and the docs have something to point at.
pub const PPI_EL1_PHYS_TIMER: u32 = 30;

/// Enable a per-PE SGI (intid 0..15) or PPI (intid 16..31)
/// on `cpu_id`'s redistributor. Same index-assumption caveat as
/// [`init_redistributor`]; see [`enable_ppi_at`] for the address-based
/// form the affinity-walk SMP path uses.
#[cfg(target_arch = "aarch64")]
pub fn enable_ppi(cpu_id: usize, intid: u32) {
    enable_ppi_at(GICR_BASE + cpu_id * GICR_STRIDE, intid);
}

/// Enable a per-PE SGI (intid 0..15) or PPI (intid 16..31) on the
/// redistributor frame whose `RD_base` is `rd_base`.
#[cfg(target_arch = "aarch64")]
pub fn enable_ppi_at(rd_base: usize, intid: u32) {
    debug_assert!(intid < 32, "use enable_spi for INTIDs >= 32");
    let sgi_base = rd_base + GICR_SGI_OFFSET;
    let bit = 1u32 << intid;
    unsafe {
        mmio_write32(sgi_base + GICR_ISENABLER0, bit);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Redistributor-frame discovery + SGI send — the SMP building blocks.
// ──────────────────────────────────────────────────────────────────────────

/// Safety bound on [`find_redistributor`]'s walk. QEMU virt `-smp 4`
/// needs 4 frames; this is a generous multiple so real multi-socket
/// systems aren't cut short, while still being finite — an unbounded
/// walk that never sees `TYPER.Last` (firmware bug, or a caller that
/// under-mapped the MMIO window) would otherwise read off the end of
/// whatever IS mapped.
pub const GICR_WALK_MAX_FRAMES: usize = 16;

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn mmio_read64(addr: usize) -> u64 {
    core::ptr::read_volatile(addr as *const u64)
}

/// Walk redistributor frames from `GICR_BASE`, reading each one's own
/// `GICR_TYPER` (never assuming a uniform stride or index == core id —
/// see [`typer_affinity_key`]/[`typer_frame_stride`]'s docs), and return
/// the `RD_base` of the frame whose affinity matches `target_affinity`
/// (pack with [`crate::mpidr::affinity_key`] /
/// [`crate::mpidr::mpidr_affinity_key`]).
///
/// `max_frames` bounds the walk to however many frames the caller has
/// actually MMIO-mapped — capped further by [`GICR_WALK_MAX_FRAMES`].
/// Stops early at the frame with `TYPER.Last` set. Returns `None` if the
/// walk exhausts its bound or reaches `Last` without a match.
#[cfg(target_arch = "aarch64")]
pub fn find_redistributor(target_affinity: u32, max_frames: usize) -> Option<usize> {
    let mut rd_base = GICR_BASE;
    for _ in 0..max_frames.min(GICR_WALK_MAX_FRAMES) {
        let typer = unsafe { mmio_read64(rd_base + GICR_TYPER) };
        if typer_affinity_key(typer) == target_affinity {
            return Some(rd_base);
        }
        if typer_is_last(typer) {
            break;
        }
        rd_base += typer_frame_stride(typer);
    }
    None
}

/// Send SGI `intid` (0..=15) to the PE identified by `target_affinity`
/// (pack with [`crate::mpidr::affinity_key`] / [`sgi1r_encode`]'s own
/// caller contract). The receiving PE picks it up via [`iar1`] and must
/// [`eoir1`] it — same acknowledge/EOI path as any other Group-1
/// interrupt; SGIs need no separate receive primitive.
///
/// `dsb ishst` orders any store this PE made before the send (e.g.
/// writing a payload the target will read once woken) ahead of the SGI
/// itself being observable — without it, nothing stops the interrupt
/// from being delivered before the store the handler depends on has left
/// this PE's write buffer, which racing on `send_sgi` used for anything
/// beyond a bare wakeup would hit.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn send_sgi(target_affinity: u32, intid: u8) {
    let val = sgi1r_encode(target_affinity, intid);
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "msr ICC_SGI1R_EL1, {0}",
            "isb",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Acknowledge the highest-priority pending Group 1 interrupt
/// and return its INTID. The companion `eoir1` MUST be called
/// after handling.
#[cfg(target_arch = "aarch64")]
pub fn iar1() -> u32 {
    let id: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, ICC_IAR1_EL1",
            out(reg) id,
            options(nomem, nostack, preserves_flags),
        );
    }
    id as u32
}

/// Signal end-of-interrupt for `intid` returned by `iar1`.
#[cfg(target_arch = "aarch64")]
pub fn eoir1(intid: u32) {
    unsafe {
        core::arch::asm!(
            "msr ICC_EOIR1_EL1, {0}",
            in(reg) intid as u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────
// LPIs (Locality-specific Peripheral Interrupts) — the redistributor half
// of ITS-routed MSI/MSI-X delivery (RFC-0046 stage 1a, [`crate::its`]
// carries the ITS-side half: command queue, device/ITT tables). An LPI is
// never a Group-0/1 SPI/PPI/SGI: it has no GICD_* or GICR_I{S,C}ENABLER0
// bit, no priority register in the fixed 0..1019 range — its only enable
// gate is the config-table byte [`propbaser_value`] points at, and its
// only mask is `GICR_CTLR.EnableLPIs` below. `iar1`/`eoir1` are unchanged:
// an LPI's INTID (>= [`LPI_INTID_BASE`]) comes back from `ICC_IAR1_EL1`
// exactly like any other Group 1 interrupt, and `ICC_EOIR1_EL1` still
// ends it — this section only adds what makes that INTID arrive at all.
//
// # Memory attributes for the LPI tables — Normal WB Inner-Shareable, not
// Device
//
// GICR_PROPBASER/PENDBASER's own cacheability/shareability fields tell the
// redistributor HOW to access the table; they say nothing about how the
// CPU wrote it, so the two must agree or one side sees stale data. This
// driver picks Normal, Write-Back, Inner-Shareable (`GIC_BASER_CACHE_
// RaWaWb` = 7, `GIC_BASER_InnerShareable` = 1 in the ARM GIC architecture
// spec's own naming) for three reasons: (1) it is what QEMU's ITS/GICv3
// emulation actually assumes — it accesses guest RAM through the same
// coherent path as the vCPU, so a Device-memory or non-cacheable table
// would only add overhead, not correctness; (2) the kernel's own identity
// map already puts every RAM page at `MAIR_IDX_NORMAL` with `SH[1:0] =
// 0b11` (Inner Shareable — see `mmu.rs`'s own comment on that constant),
// so a LPI table backed by an ordinary `static` needs NO special mapping,
// just a barrier; (3) `send_sgi` already establishes the precedent in
// this same file: `dsb ishst` before the doorbell, not a cache clean —
// Inner-Shareable Normal memory is coherent within the ordering domain a
// `dsb ish*` closes, so the CPU-write-then-ITS-read handoff needs only
// that barrier, never `dc civac`/`dc cvac`. A real board whose ITS is
// NOT in the same inner-shareable domain as the CPUs (rare — GICv3 ITS is
// specified to be a coherent observer) would need Device-nGnRE tables
// and explicit cache maintenance instead; nothing here detects that case.
//
// # Why `id_bits` is fixed at 13, not computed from the LPI count in use
//
// `GICR_PROPBASER.IDbits` sizes the WHOLE table (`2^(id_bits+1)` one-byte
// entries covering INTID 0..2^(id_bits+1)-1), not just the LPIs this
// driver programs — and LPIs start at INTID 8192, so `id_bits` must be at
// least 13 (`2^14 = 16384` entries) just to have ONE valid LPI slot ---
// picking anything smaller is not a valid size to shrink, it is a
// mis-sized table an ITS would refuse or read out of bounds. 13 is
// therefore both the minimum and this driver's choice — using it is not
// "assuming few LPIs", it is "as small as the architecture allows".
pub const LPI_INTID_BASE: u32 = 8192;

/// `GICR_PROPBASER.IDbits` this driver programs — see the module-section
/// doc above for why 13 is a floor, not a policy knob.
pub const LPI_ID_BITS: u8 = 13;

/// Byte size of the LPI configuration table `LPI_ID_BITS` implies:
/// `2^(id_bits+1)` one-byte entries. 16 KiB for `LPI_ID_BITS == 13`.
pub const fn lpi_prop_table_size(id_bits: u8) -> usize {
    1usize << (id_bits as u32 + 1)
}

const GICR_CTLR_ENABLE_LPIS: u32 = 1 << 0;
/// GICR_CTLR.RWP (bit 3) — Register Write Pending. Same role as the
/// distributor's own RWP ([`GICD_CTLR_RWP`]): a caller that pokes
/// PROPBASER/PENDBASER and does not wait for this to clear has no
/// guarantee the redistributor has latched either pointer yet.
const GICR_CTLR_RWP: u32 = 1 << 3;

const GICR_PROPBASER_OFF: usize = 0x0070;
const GICR_PENDBASER_OFF: usize = 0x0078;

/// `GIC_BASER_CACHE_RaWaWb` (architecture spec naming) — Normal,
/// Read-allocate, Write-allocate, Write-Back. Shared by every BASER-shaped
/// register this driver programs (GITS_CBASER/BASERn in `its.rs`,
/// GICR_PROPBASER/PENDBASER here) — see the module-section doc for why.
pub const BASER_CACHE_RAWAWB: u64 = 0b111;
/// `GIC_BASER_InnerShareable`.
pub const BASER_SHAREABILITY_INNER: u64 = 0b01;

/// GICR_TYPER.PLPIS (bit 0) — this redistributor frame implements
/// physical LPIs at all. A frame without it has no GICR_PROPBASER/
/// PENDBASER worth writing — callers must check this before
/// [`enable_lpis_at`].
pub const fn typer_supports_plpis(typer: u64) -> bool {
    typer & 1 != 0
}

/// GICR_TYPER's "Processor Number" field, bits `[23:8]` — NOT the
/// affinity field [`typer_affinity_key`] decodes at `[63:32]`. This is
/// what an ITS with `GITS_TYPER.PTA == 0` (`its::typer_pta`) wants as a
/// collection's target: [`crate::its::cmd_mapc`]'s `target` argument is
/// this value shifted left by 16 (the position `its_encode_target`'s
/// `>> 16` / `[51:16]` field puts it at) — [`crate::its::collection_target_cpu_number`]
/// does that shift so no caller hand-rolls it twice.
pub const fn typer_cpu_number(typer: u64) -> u16 {
    ((typer >> 8) & 0xffff) as u16
}

/// Encode `GICR_PROPBASER`: the LPI configuration table pointer, shared
/// across every redistributor that enables LPIs (one physical table, one
/// value, written identically everywhere — unlike PENDBASER below). Low
/// 12 bits of `phys_base` are masked off (4 KiB alignment, architectural
/// `[51:12]` address field); `id_bits` should be [`LPI_ID_BITS`].
pub const fn propbaser_value(phys_base: u64, id_bits: u8) -> u64 {
    (phys_base & 0x000f_ffff_ffff_f000)
        | (BASER_CACHE_RAWAWB << 7)
        | (BASER_SHAREABILITY_INNER << 10)
        | (id_bits as u64 & 0x1f)
}

/// Encode `GICR_PENDBASER`: the LPI pending-state bitmap, ONE PER
/// REDISTRIBUTOR (never shared — two redistributors sharing a pending
/// table would each think the other's LPI delivery is its own). Low 16
/// bits of `phys_base` are masked off: the architectural address field is
/// `[51:16]`, i.e. **64 KiB alignment**, stricter than PROPBASER's 4 KiB —
/// verified against `GICR_PENDBASER_ADDRESS`'s own mask
/// (`GENMASK_ULL(51,16)` vs PROPBASER's `GENMASK_ULL(51,12)`) rather than
/// assumed uniform with PROPBASER, which is exactly the kind of
/// off-by-a-field-width mistake this project's own canary discipline
/// exists to catch. `ptz`: true if the caller already zeroed the table
/// (lets the redistributor skip its own zeroing pass) — this driver's
/// caller always zeroes its `static` before calling, so always passes
/// `true`.
pub const fn pendbaser_value(phys_base: u64, ptz: bool) -> u64 {
    const PTZ_BIT: u64 = 1 << 62;
    (phys_base & 0x000f_ffff_ffff_0000)
        | (BASER_CACHE_RAWAWB << 7)
        | (BASER_SHAREABILITY_INNER << 10)
        | if ptz { PTZ_BIT } else { 0 }
}

/// Enable LPIs on the redistributor frame at `rd_base`: program
/// PROPBASER/PENDBASER, wait RWP, then set `GICR_CTLR.EnableLPIs`.
///
/// **Order matters and is architecturally mandated**: PROPBASER/PENDBASER
/// must be written WHILE `EnableLPIs == 0` (a redistributor is permitted
/// to ignore the write otherwise) — this function sets them first,
/// unconditionally, rather than trusting a caller to have left LPIs
/// disabled. `prop_table_pa`/`pend_table_pa` must already be zeroed (this
/// function does not zero them — the caller's `static` init does) and
/// satisfy PROPBASER's 4 KiB / PENDBASER's 64 KiB alignment respectively
/// (see the two `*_value` functions' docs); an unaligned pointer is
/// silently truncated by the register's own address-field mask, not
/// rejected — a caller passing one gets a wrong table, not a fault.
#[cfg(target_arch = "aarch64")]
pub fn enable_lpis_at(rd_base: usize, prop_table_pa: u64, pend_table_pa: u64) {
    unsafe {
        mmio_write64(rd_base + GICR_PROPBASER_OFF, propbaser_value(prop_table_pa, LPI_ID_BITS));
        mmio_write64(rd_base + GICR_PENDBASER_OFF, pendbaser_value(pend_table_pa, true));

        let mut spins = 0u32;
        while mmio_read32(rd_base + GICR_CTLR) & GICR_CTLR_RWP != 0 && spins < GICR_WAKE_MAX_SPINS {
            core::hint::spin_loop();
            spins += 1;
        }

        let ctlr = mmio_read32(rd_base + GICR_CTLR);
        mmio_write32(rd_base + GICR_CTLR, ctlr | GICR_CTLR_ENABLE_LPIS);
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn mmio_write64(addr: usize, val: u64) {
    core::ptr::write_volatile(addr as *mut u64, val);
}
