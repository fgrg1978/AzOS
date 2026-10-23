// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Raspberry Pi 2/3 interrupt controllers, for a machine with no GIC: the
//! BCM2836 ARM-local controller (`brcm,bcm2836-l1-intc`: per-core timer
//! interrupts, four mailboxes per core, the PMU, and the line the GPU's
//! interrupts arrive on) and behind it the BCM2835 "armctrl" controller
//! (`brcm,bcm2836-armctrl-ic`: the peripherals' 72 lines in three banks).
//!
//! The boot selects it ([`select`]) when the device tree names both nodes;
//! `azos_drv_irqchip::gic` makes the choice. Every `irq::gic` function then
//! comes here, so the callers (the IRQ handler, the IPI sender, the console
//! and ring-3 line bindings) keep the GIC's vocabulary of INTIDs:
//!
//! | INTID      | source                                                      |
//! |------------|-------------------------------------------------------------|
//! | 0..=15     | SGI `n`: bit `n` of the target core's mailbox 0             |
//! | 23         | the PMU (local source 9)                                    |
//! | 26, 27     | the EL2 physical timer, the virtual timer (local 2, 3)      |
//! | 29, 30     | the secure and non-secure EL1 physical timers (local 0, 1)  |
//! | 32 + `h`   | armctrl line `h = bank * 32 + n` (bank 0: the ARM block's   |
//! |            | eight, banks 1 and 2: GPU interrupts 0..31 and 32..63)      |
//!
//! The PPI numbers are the ones the generic timer's and the PMU's GIC
//! bindings use, so `PPI_VIRT_TIMER` means the same line on either machine.
//!
//! What differs from a GIC: no priorities, no trigger configuration (every
//! line is a level), and no per-line routing. The GPU's interrupts go to one
//! core together (`GPU_INT_ROUTING`, core 0 at reset, which is left as is);
//! a bind to another core is enabled where it is. An SGI is acknowledged when
//! it is read ([`iar`] clears its mailbox bit), so the end of an interrupt
//! ([`eoir`]) has nothing to write.
//!
//! References: BCM2836 "ARM Quad A7 core" (QA7) for the local block; BCM2835
//! ARM Peripherals §7 for armctrl; Linux `irq-bcm2836.c` and `irq-bcm2835.c`
//! for how the two are walked. The pure halves (the INTID mapping, the
//! pending-word decode) compile everywhere so the host tests run them as
//! written; only the MMIO is `aarch64`-gated.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ──────────────────────────────────────────────────────────────────────────
// Local controller registers (QA7 §4)
// ──────────────────────────────────────────────────────────────────────────

const LOCAL_PMU_ROUTE_SET: usize = 0x10;
const LOCAL_PMU_ROUTE_CLR: usize = 0x14;
/// Core `n`'s timer interrupt control: bits 0..3 send CNTPS, CNTPNS, CNTHP,
/// CNTV to the core's IRQ.
const LOCAL_TIMER_INT_CTRL0: usize = 0x40;
/// Core `n`'s mailbox interrupt control: bits 0..3 send mailboxes 0..3 to its
/// IRQ.
const LOCAL_MAILBOX_INT_CTRL0: usize = 0x50;
/// Core `n`'s IRQ source.
const LOCAL_IRQ_PENDING0: usize = 0x60;
/// Mailbox 0 of core `n`: write-set at `0x80 + 16n`, read and
/// write-one-to-clear at `0xC0 + 16n`.
const LOCAL_MAILBOX0_SET0: usize = 0x80;
const LOCAL_MAILBOX0_CLR0: usize = 0xC0;

/// The local IRQ-source bits.
const SRC_MAILBOX0: u32 = 1 << 4;
const SRC_GPU: u32 = 1 << 8;

// ──────────────────────────────────────────────────────────────────────────
// armctrl registers (BCM2835 ARM Peripherals §7.5, from the node's `reg`)
// ──────────────────────────────────────────────────────────────────────────

const ARM_PENDING_BASIC: usize = 0x00;
const ARM_PENDING1: usize = 0x04;
const ARM_PENDING2: usize = 0x08;
/// The enable and disable registers, indexed by bank (0: the basic one).
const ARM_ENABLE: [usize; 3] = [0x18, 0x10, 0x14];
const ARM_DISABLE: [usize; 3] = [0x24, 0x1C, 0x20];

/// Lines per armctrl bank; bank 0 has eight.
const BANK_LINES: u32 = 32;
/// The number of armctrl lines: 32 + 8 would leave a gap, so the INTID space
/// is three whole banks.
pub const ARMCTRL_LINES: u32 = 3 * BANK_LINES;
/// The first INTID past the controller's: what `gic::note_spi_limit`'s twin
/// records, so ring 3 cannot bind past it.
pub const INTID_LIMIT: u32 = 32 + ARMCTRL_LINES;

// ──────────────────────────────────────────────────────────────────────────
// Pure mapping — no `target_arch` gate
// ──────────────────────────────────────────────────────────────────────────

/// The INTID of a local source (`brcm,bcm2836-l1-intc`'s first cell). The
/// mailboxes (4..7) are SGIs, not named by a source number; the GPU line (8)
/// is the armctrl cascade.
pub const fn local_intid(hwirq: u32) -> Option<u32> {
    match hwirq {
        0 => Some(29),
        1 => Some(30),
        2 => Some(26),
        3 => Some(27),
        9 => Some(23),
        _ => None,
    }
}

/// The local timer-control bit of a PPI (the inverse of [`local_intid`] for
/// the four timers).
pub const fn timer_bit(intid: u32) -> Option<u32> {
    match intid {
        29 => Some(0),
        30 => Some(1),
        26 => Some(2),
        27 => Some(3),
        _ => None,
    }
}

/// The INTID of armctrl line `n` of `bank` (`brcm,bcm2836-armctrl-ic`'s two
/// cells). Bank 0 has eight lines.
pub const fn armctrl_intid(bank: u32, n: u32) -> Option<u32> {
    if bank > 2 || n >= BANK_LINES || (bank == 0 && n >= 8) {
        return None;
    }
    Some(32 + bank * BANK_LINES + n)
}

/// `(bank, bit)` of an armctrl INTID.
pub const fn armctrl_line(intid: u32) -> Option<(usize, u32)> {
    if intid < 32 || intid >= INTID_LIMIT {
        return None;
    }
    let h = intid - 32;
    Some(((h / BANK_LINES) as usize, h % BANK_LINES))
}

/// The basic-pending word's bits: the ARM block's eight lines, "bank 1 / bank
/// 2 has more", and the eleven GPU lines it repeats ("shortcuts").
const BASIC_ARM: u32 = 0xFF;
const BASIC_BANK1: u32 = 1 << 8;
const BASIC_BANK2: u32 = 1 << 9;
const SHORTCUT1: u32 = 0x0000_7C00;
const SHORTCUT2: u32 = 0x001F_8000;
const SHORTCUT_SHIFT: u32 = 10;
/// The GPU line each shortcut bit stands for, in its bank (Linux
/// `irq-bcm2835.c`'s `shortcuts`): bits 10..14 are bank 1's 7, 9, 10, 18,
/// 19, bits 15..20 bank 2's 21..25 and 30.
const SHORTCUTS: [u32; 11] = [7, 9, 10, 18, 19, 21, 22, 23, 24, 25, 30];

/// The armctrl line to take next, from the three pending words, as Linux
/// walks them: an ARM-block line first, then a shortcut, then bank 1, then
/// bank 2. `None` when nothing is pending.
pub const fn next_armctrl_line(basic: u32, pending1: u32, pending2: u32) -> Option<u32> {
    let valid = basic & (BASIC_ARM | BASIC_BANK1 | BASIC_BANK2 | SHORTCUT1 | SHORTCUT2);
    if valid == 0 {
        return None;
    }
    if valid & BASIC_ARM != 0 {
        return Some((valid & BASIC_ARM).trailing_zeros());
    }
    if valid & SHORTCUT1 != 0 {
        let i = ((valid & SHORTCUT1) >> SHORTCUT_SHIFT).trailing_zeros() as usize;
        return Some(BANK_LINES + SHORTCUTS[i]);
    }
    if valid & SHORTCUT2 != 0 {
        let i = ((valid & SHORTCUT2) >> SHORTCUT_SHIFT).trailing_zeros() as usize;
        return Some(2 * BANK_LINES + SHORTCUTS[i]);
    }
    if valid & BASIC_BANK1 != 0 && pending1 != 0 {
        return Some(BANK_LINES + pending1.trailing_zeros());
    }
    if valid & BASIC_BANK2 != 0 && pending2 != 0 {
        return Some(2 * BANK_LINES + pending2.trailing_zeros());
    }
    None
}

/// What a core's IRQ source word says to take: an SGI from mailbox 0 (`mbox`
/// is that mailbox's word), a timer or the PMU, or the armctrl cascade
/// (`Cascade`). In that order: an IPI before the tick, the tick before a
/// peripheral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Sgi(u32),
    Local(u32),
    Cascade,
    None,
}

pub const fn decode_source(src: u32, mbox: u32) -> Source {
    if src & SRC_MAILBOX0 != 0 && mbox != 0 {
        let n = mbox.trailing_zeros();
        if n < 16 {
            return Source::Sgi(n);
        }
    }
    let mut bit = 0;
    while bit < 4 {
        if src & (1 << bit) != 0 {
            if let Some(i) = local_intid(bit) {
                return Source::Local(i);
            }
        }
        bit += 1;
    }
    if src & (1 << 9) != 0 {
        return Source::Local(23);
    }
    if src & SRC_GPU != 0 {
        return Source::Cascade;
    }
    Source::None
}

// ──────────────────────────────────────────────────────────────────────────
// Selection
// ──────────────────────────────────────────────────────────────────────────

static ACTIVE: AtomicBool = AtomicBool::new(false);
static LOCAL: AtomicUsize = AtomicUsize::new(0);
static LOCAL_SIZE: AtomicUsize = AtomicUsize::new(0);
static ARMCTRL: AtomicUsize = AtomicUsize::new(0);
static ARMCTRL_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Select this backend: the local controller at `local` (`local_size` bytes)
/// and armctrl at `armctrl`. Boot calls it once, before any `irq::gic`
/// function runs and before the windows are mapped (read back through
/// [`windows`]).
pub fn select(local: usize, local_size: usize, armctrl: usize, armctrl_size: usize) {
    LOCAL.store(local, Ordering::Relaxed);
    LOCAL_SIZE.store(local_size, Ordering::Relaxed);
    ARMCTRL.store(armctrl, Ordering::Relaxed);
    ARMCTRL_SIZE.store(armctrl_size, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Release);
}

/// Whether the BCM2836 pair is the controller of this boot.
#[inline(always)]
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// The two MMIO windows the boot maps: `(local, armctrl)`, each `(base, bytes)`.
pub fn windows() -> [(usize, usize); 2] {
    [
        (LOCAL.load(Ordering::Relaxed), LOCAL_SIZE.load(Ordering::Relaxed)),
        (ARMCTRL.load(Ordering::Relaxed), ARMCTRL_SIZE.load(Ordering::Relaxed)),
    ]
}

// ──────────────────────────────────────────────────────────────────────────
// MMIO
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn read32(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn write32(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn local() -> usize {
    LOCAL.load(Ordering::Relaxed)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn armctrl() -> usize {
    ARMCTRL.load(Ordering::Relaxed)
}

/// The calling core's number in the local block: its MPIDR `Aff0` (the four
/// Cortex-A53s of a BCM2837 are cluster 0, cores 0..3).
#[cfg(target_arch = "aarch64")]
#[inline]
fn my_core() -> usize {
    (crate::cpu::read_mpidr().affinity_key() & 0x3) as usize
}

/// Every armctrl line disabled. The local block's prescaler and timer source
/// are the firmware's (they set the generic timer's rate, which the kernel
/// reads from `CNTFRQ_EL0`), and the GPU's interrupts stay routed to core 0.
#[cfg(target_arch = "aarch64")]
pub fn init_distributor() {
    let a = armctrl();
    unsafe {
        for off in ARM_DISABLE {
            write32(a + off, 0xFFFF_FFFF);
        }
    }
}

/// The calling core: its timer and mailbox interrupts off, its mailbox 0
/// cleared. [`enable_ppi`] turns individual sources on.
#[cfg(target_arch = "aarch64")]
pub fn init_cpu_interface() {
    let l = local();
    let c = my_core();
    unsafe {
        write32(l + LOCAL_TIMER_INT_CTRL0 + 4 * c, 0);
        write32(l + LOCAL_MAILBOX_INT_CTRL0 + 4 * c, 0);
        write32(l + LOCAL_MAILBOX0_CLR0 + 16 * c, 0xFFFF_FFFF);
    }
}

/// Send the SGI or PPI `intid` to the calling core: an SGI is mailbox 0's
/// interrupt, a timer its control bit, the PMU its routing bit.
#[cfg(target_arch = "aarch64")]
pub fn enable_ppi(intid: u32) {
    set_ppi(intid, true);
}

/// Stop the SGI or PPI `intid` on the calling core.
#[cfg(target_arch = "aarch64")]
pub fn disable_ppi(intid: u32) {
    set_ppi(intid, false);
}

#[cfg(target_arch = "aarch64")]
fn set_ppi(intid: u32, on: bool) {
    let l = local();
    let c = my_core();
    let (reg, bit) = if intid < 16 {
        (LOCAL_MAILBOX_INT_CTRL0 + 4 * c, 0)
    } else if intid == 23 {
        unsafe { write32(l + if on { LOCAL_PMU_ROUTE_SET } else { LOCAL_PMU_ROUTE_CLR }, 1 << c) };
        return;
    } else if let Some(b) = timer_bit(intid) {
        (LOCAL_TIMER_INT_CTRL0 + 4 * c, b)
    } else {
        return;
    };
    unsafe {
        let v = read32(l + reg);
        write32(l + reg, if on { v | 1 << bit } else { v & !(1 << bit) });
    }
}

/// Enable armctrl line `intid`.
#[cfg(target_arch = "aarch64")]
pub fn enable_spi(intid: u32) {
    if let Some((bank, bit)) = armctrl_line(intid) {
        unsafe { write32(armctrl() + ARM_ENABLE[bank], 1 << bit) };
    }
}

/// Disable armctrl line `intid`.
#[cfg(target_arch = "aarch64")]
pub fn disable_spi(intid: u32) {
    if let Some((bank, bit)) = armctrl_line(intid) {
        unsafe {
            write32(armctrl() + ARM_DISABLE[bank], 1 << bit);
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
    }
}

/// `(router, edge, enabled)` of armctrl line `intid`, as `gic::spi_state`
/// reports them: the router is the core the GPU's interrupts go to (0, left
/// at its reset value), never edge.
#[cfg(target_arch = "aarch64")]
pub fn spi_state(intid: u32) -> (u64, bool, bool) {
    let Some((bank, bit)) = armctrl_line(intid) else { return (0, false, false) };
    let en = unsafe { read32(armctrl() + ARM_ENABLE[bank]) };
    (0, false, en & (1 << bit) != 0)
}

/// Send SGI `intid` to the core with affinity `target_affinity`: a bit of its
/// mailbox 0.
#[cfg(target_arch = "aarch64")]
pub fn send_sgi(target_affinity: u32, intid: u8) {
    let core = (target_affinity & 0x3) as usize;
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
        write32(local() + LOCAL_MAILBOX0_SET0 + 16 * core, 1 << (intid & 0xF));
    }
}

/// The interrupt to handle (1023 when none): the calling core's source word
/// decoded ([`decode_source`]), an SGI acknowledged by clearing its mailbox
/// bit, an armctrl line found through the pending words.
#[cfg(target_arch = "aarch64")]
pub fn iar() -> u32 {
    let l = local();
    let c = my_core();
    unsafe {
        let src = read32(l + LOCAL_IRQ_PENDING0 + 4 * c);
        let mbox = if src & SRC_MAILBOX0 != 0 { read32(l + LOCAL_MAILBOX0_CLR0 + 16 * c) } else { 0 };
        match decode_source(src, mbox) {
            Source::Sgi(n) => {
                write32(l + LOCAL_MAILBOX0_CLR0 + 16 * c, 1 << n);
                n
            }
            Source::Local(i) => i,
            Source::Cascade => {
                let a = armctrl();
                let (b, p1, p2) = (read32(a + ARM_PENDING_BASIC), read32(a + ARM_PENDING1), read32(a + ARM_PENDING2));
                next_armctrl_line(b, p1, p2).map_or(1023, |h| 32 + h)
            }
            Source::None => 1023,
        }
    }
}

/// Nothing to end: the SGI was acknowledged by [`iar`], every other line is a
/// level its device drops.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn eoir(_intid: u32) {}
