// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// PLIC (Platform-Level Interrupt Controller) driver.
///
/// Manages external device interrupts on RISC-V.
/// Base address: 0x0c00_0000 (QEMU virt machine).
///
/// Ported from kernel/core/irq.c (PLIC parts) + kernel/include/irq.h

// ---- PLIC register layout ----
// Same base address on QEMU virt and VisionFive 2 / JH7110 (both at 0x0C00_0000).
// The CONTEXT NUMBERING is NOT the same — see `s_context` (U05-1).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use azos_arch::{Interrupts, ARCH};

use azos_drv_base::platform::hw::PLIC_BASE;

/// Priority register for IRQ `n` (0-127). Write priority 0-7.
#[inline(always)]
fn priority_addr(irq: u32) -> usize {
    PLIC_BASE + (irq as usize) * 4
}

/// The S-mode PLIC context for a hart, board-dependent. `None` means this
/// hart has no S-mode context at all and every S-mode PLIC register access
/// for it must be skipped rather than aimed at a made-up context.
///
/// **QEMU virt** (default, and `k1` until re-verified): `interrupts-extended`
/// gives every hart, hart 0 included, an M-mode context then an S-mode one,
/// in hart order — context `2*hart + 1` is S-mode for every hart. This is
/// `hw/riscv/virt.c`'s own PLIC wiring and was already correct.
///
/// **VF2 (JH7110)**: confirmed against mainline `jh7110.dtsi`'s plic node —
/// `interrupts-extended = <&cpu0_intc 11>, <&cpu1_intc 11>, <&cpu1_intc 9>,
/// <&cpu2_intc 11>, <&cpu2_intc 9>, <&cpu3_intc 11>, <&cpu3_intc 9>,
/// <&cpu4_intc 11>, <&cpu4_intc 9>` (IRQ 11 = M-mode external, 9 = S-mode
/// external, per the RISC-V privileged spec). `cpu0` is the S7 monitor
/// core (`sifive,s7`) and contributes ONE context (M-mode only — S7 cannot
/// run S-mode code at all, so it has no S-mode external-interrupt line to
/// wire). `cpu1..cpu4` are the U74 application cores (`sifive,u74-mc`,
/// mhartid 1..4) and each contribute two: M then S. Counting contexts in
/// document order: hart0→ctx0(M, no S); hart1→ctx1(M),ctx2(S);
/// hart2→ctx3(M),ctx4(S); hart3→ctx5(M),ctx6(S); hart4→ctx7(M),ctx8(S). So
/// **S-context(h) = 2h for h in 1..=4; h=0 (S7) has none.** The previous
/// `hart*2+1` formula gave hart 0 context 1 (S7's own M-mode context, not
/// an S-mode one) and every U74 hart the WRONG S-context (off by the S7
/// contribution) — `enable_irq`/`claim`/`complete` for the boot hart's
/// console IRQ were programming a context that is either M-mode-only or
/// belongs to a different physical hart.
///
/// This does **not** by itself fix VF2 IRQ delivery: it assumes the
/// kernel's own `hart` parameter already IS the physical `mhartid` (1..4 on
/// this board, since S7 = mhartid 0 cannot run this kernel) — the
/// physical→logical hart map `boot_hooks.rs` says VF2 still needs is a
/// separate, larger fix (not this file's to make; see that file's `hart_id
/// >= crate::MAX_CPUS` guard comment).
#[inline(always)]
fn s_context(hart: u32) -> Option<usize> {
    if cfg!(feature = "vf2") {
        if hart == 0 || hart > 4 { None } else { Some(2 * hart as usize) }
    } else {
        Some(hart as usize * 2 + 1)
    }
}

/// Enable register base for a hart's S-mode context. `None` when the hart
/// has no S-mode context (see [`s_context`]) — every caller below must
/// treat that as "nothing to do", not fall back to a guessed context.
#[inline(always)]
fn enable_addr(hart: u32, irq: u32) -> Option<usize> {
    let context = s_context(hart)?;
    Some(PLIC_BASE + 0x2000 + context * 0x80 + (irq as usize / 32) * 4)
}

/// Threshold register for a hart's S-mode context.
#[inline(always)]
fn threshold_addr(hart: u32) -> Option<usize> {
    let context = s_context(hart)?;
    Some(PLIC_BASE + 0x20_0000 + context * 0x1000)
}

/// Claim/complete register for a hart's S-mode context.
#[inline(always)]
fn claim_addr(hart: u32) -> Option<usize> {
    let context = s_context(hart)?;
    Some(PLIC_BASE + 0x20_0000 + context * 0x1000 + 4)
}

// ---- MMIO helpers (same volatile pattern as UART) ----

#[inline(always)]
fn mmio_read32(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

#[inline(always)]
fn mmio_write32(addr: usize, val: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// ---- Public API ----

/// Maximum number of interrupt sources.
/// K1 (SpacemiT) supports 256 sources; QEMU/VF2 support 128.
#[cfg(feature = "k1")]
pub const MAX_IRQS: u32 = 256;
#[cfg(not(feature = "k1"))]
pub const MAX_IRQS: u32 = 128;

/// Initialize the PLIC for `hart`: the global half once ([`init_global`]),
/// then this hart's own context ([`init_hart`]).
///
/// Every hart that takes supervisor external interrupts calls this (the boot
/// hart in its interrupt bring-up, each secondary in `smp_secondary_start`).
/// Before, it rewrote every source's priority to 1 on each call: priorities
/// are global, so a second call — a secondary's init, or any later re-init —
/// unmasked the ring-3 lines `user_irq` holds masked at priority 0 until
/// their ACK.
pub fn init(hart: u32) {
    init_global();
    init_hart(hart);
}

/// Set once by [`init_global`]'s first call.
static GLOBAL_DONE: AtomicBool = AtomicBool::new(false);

const IMPL_WORDS: usize = (MAX_IRQS as usize).div_ceil(32);

/// Sources whose priority register is implemented, found by
/// [`init_global`]: the PLIC spec makes priority WARL and an unimplemented
/// source's register reads 0 whatever is written. QEMU `virt` has sources
/// 1..=95 (`riscv,ndev = <0x5f>`) against [`MAX_IRQS`] = 128.
static IMPLEMENTED: [AtomicU32; IMPL_WORDS] = [const { AtomicU32::new(0) }; IMPL_WORDS];

/// The global half of [`init`], effective ONCE: every source's priority to 1
/// ("may interrupt" at threshold 0) and the implemented-source probe. A
/// second call returns at once, and a source ring 3 owns is skipped even on
/// the first (its priority is `user_irq`'s mask: 0 until its ACK).
///
/// Runs at boot before any ring-3 bind, so the probe's read-back cannot race
/// the external-interrupt handler's mask of a live line — which a read-back
/// at bind time would.
pub fn init_global() {
    if GLOBAL_DONE.swap(true, Ordering::AcqRel) {
        return;
    }
    for irq in 1..MAX_IRQS {
        if crate::user_irq::owned(irq) {
            continue;
        }
        set_priority(irq, 1);
        if mmio_read32(priority_addr(irq)) != 0 {
            IMPLEMENTED[(irq / 32) as usize].fetch_or(1 << (irq % 32), Ordering::Relaxed);
        }
    }
}

/// The per-hart half of [`init`]: this hart's S-mode context accepts every
/// priority above 0 (threshold 0; OpenSBI leaves it at 7, "mask all"). The
/// context's enable bits are left alone: they are the routing
/// (`user_irq::bind`), and a re-init must not drop it. No-op when `hart` has
/// no S-mode context ([`s_context`]).
pub fn init_hart(hart: u32) {
    if let Some(addr) = threshold_addr(hart) {
        mmio_write32(addr, 0);
    }
}

/// Whether source `irq` exists on this PLIC ([`init_global`]'s probe).
/// `false` before the probe ran.
pub fn implemented(irq: u32) -> bool {
    if irq == 0 || irq >= MAX_IRQS {
        return false;
    }
    IMPLEMENTED[(irq / 32) as usize].load(Ordering::Relaxed) & (1 << (irq % 32)) != 0
}

/// Whether `hart` has an S-mode context ([`s_context`]): whether a line can
/// be routed to it at all.
pub fn has_s_context(hart: u32) -> bool {
    s_context(hart).is_some()
}

/// Set the priority (0-7) for an interrupt source.
pub fn set_priority(irq: u32, priority: u32) {
    if irq == 0 || irq >= MAX_IRQS { return; }
    mmio_write32(priority_addr(irq), priority & 0x7);
}

/// Serialises the read-modify-write of the enable words. Each context's
/// enable bits share 32-bit words, and since wave 10 IRQ5 they change at run
/// time from any hart: a ring-3 bind routes its line to the binding task's
/// hart (`user_irq::bind`), and [`complete`] toggles a bit a concurrent
/// re-route cleared. Linux holds `plic_handler::enable_lock` for the same
/// reason. Taken with interrupts off: [`complete`] takes it from the
/// external-interrupt handler.
static ENABLE_LOCK: AtomicBool = AtomicBool::new(false);

fn with_enable_lock<R>(f: impl FnOnce() -> R) -> R {
    let saved = ARCH.disable_all();
    while ENABLE_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let r = f();
    ENABLE_LOCK.store(false, Ordering::Release);
    ARCH.restore(saved);
    r
}

/// Set or clear `irq`'s enable bit in `addr`'s word, under [`ENABLE_LOCK`].
fn toggle(addr: usize, irq: u32, on: bool) {
    let bit = 1u32 << (irq % 32);
    with_enable_lock(|| {
        let current = mmio_read32(addr);
        mmio_write32(addr, if on { current | bit } else { current & !bit });
    });
}

/// Enable a specific IRQ for a hart. No-op if `hart` has no S-mode context.
pub fn enable_irq(hart: u32, irq: u32) {
    if irq == 0 || irq >= MAX_IRQS { return; }
    let Some(addr) = enable_addr(hart, irq) else { return; };
    toggle(addr, irq, true);
}

/// Disable a specific IRQ for a hart. No-op if `hart` has no S-mode context.
pub fn disable_irq(hart: u32, irq: u32) {
    if irq == 0 || irq >= MAX_IRQS { return; }
    let Some(addr) = enable_addr(hart, irq) else { return; };
    toggle(addr, irq, false);
}

/// Whether `irq` is enabled for `hart`'s S-mode context (a read-back of the
/// enable bit, WARL: an unimplemented source reads 0).
pub fn is_enabled(hart: u32, irq: u32) -> bool {
    if irq == 0 || irq >= MAX_IRQS { return false; }
    match enable_addr(hart, irq) {
        Some(addr) => mmio_read32(addr) & (1 << (irq % 32)) != 0,
        None => false,
    }
}

/// Claim the highest-priority pending interrupt. Returns 0 (none pending)
/// if `hart` has no S-mode context — same "nothing to claim" value the
/// real register returns when the queue is empty.
pub fn claim(hart: u32) -> u32 {
    match claim_addr(hart) {
        Some(addr) => mmio_read32(addr),
        None => 0,
    }
}

/// Signal completion of interrupt handling.
///
/// # A source disabled for this context between claim and complete
///
/// Per the PLIC spec: "If the completion ID does not match an interrupt
/// source that is currently enabled for the target, the completion is
/// silently ignored." That happens when a ring-3 line is re-routed to
/// another hart (`user_irq::bind`, which disables the old context first)
/// while this hart has it claimed. Skipping the write — what this function
/// used to do — leaves the source claimed at the gateway forever: it never
/// interrupts again. Linux's `plic_irq_eoi` enables the source for this
/// context, writes the completion, and disables it again; so does this, under
/// [`ENABLE_LOCK`]. The common path (bit set) is unchanged: one read, one
/// write.
pub fn complete(hart: u32, irq: u32) {
    if irq == 0 || irq >= MAX_IRQS { return; }
    let Some(addr) = enable_addr(hart, irq) else { return; };
    let Some(caddr) = claim_addr(hart) else { return; };
    let bit  = 1u32 << (irq % 32);
    // Re-read enable register from hardware (not a cached software flag).
    if mmio_read32(addr) & bit != 0 {
        mmio_write32(caddr, irq);
    } else {
        complete_disabled(addr, caddr, irq);
    }
}

/// [`complete`]'s rare half, out of line so the common path stays as it was.
#[inline(never)]
fn complete_disabled(addr: usize, caddr: usize, irq: u32) {
    let bit = 1u32 << (irq % 32);
    with_enable_lock(|| {
        let current = mmio_read32(addr);
        if current & bit != 0 {
            // Re-enabled meanwhile (a route back to this hart): plain write.
            mmio_write32(caddr, irq);
            return;
        }
        mmio_write32(addr, current | bit);
        mmio_write32(caddr, irq);
        mmio_write32(addr, current);
    });
}
