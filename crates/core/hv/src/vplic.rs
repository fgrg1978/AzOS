// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtual PLIC of a RISC-V guest (`sifive,plic-1.0.0`, the controller the
//! guest device tree names): source priorities, the pending and enable bitmaps,
//! per-context threshold and the claim / complete register.
//!
//! Like [`crate::vioapic`] it is a pure model. A device model that reports its
//! line's level calls [`Vplic::set_irq`]; one that reports only that the line
//! rose (vmmd's, through `Vcpu::inject`) calls [`Vplic::pulse`]. The exit
//! handler passes an `Exit::Mmio` to [`Vplic::serve`], which answers it from
//! [`Vplic::mmio_read`] / [`Vplic::mmio_write`] when it falls inside the PLIC
//! window (the loop's `RunHost::intc_mmio`). Every operation
//! returns the [`Change`] it made to the contexts' external-interrupt lines:
//! the monitor turns a raised line into `hvip.VSEIP` on the target vCPU and a
//! lowered one into its removal (`azos_arch_riscv64` `ext::hv::inject`,
//! `hvip_level`), and kicks the vCPUs of the raised contexts.
//!
//! # Contract with the guest device tree
//!
//! A guest hart has one interrupt context, the S-level one (a guest has no
//! M-mode): **context `n` is vCPU `n`**, so the DTB's `interrupts-extended`
//! lists `<&cpuN_intc 9>` per CPU and no M-level entry. Priorities are 3 bits
//! (7 levels, like QEMU's `virt`), sources are `1..=63` (`riscv,ndev = 63`),
//! contexts are at most [`CONTEXTS`].
//!
//! # Semantics (RISC-V PLIC spec 1.0.0; where it is silent, QEMU `sifive_plic`)
//!
//! * A source is **level triggered**: the line asserted pends it, the line
//!   dropped before a claim un-pends it. That is what a virtio-mmio backend
//!   does (its interrupt status register is a level) and what a UART's
//!   interrupt-identification is.
//! * A **claim** returns the highest-priority source that is pending, enabled
//!   for the context and above its threshold (ties go to the lowest id), or 0;
//!   it clears the pending bit and closes the source's gateway: the source
//!   cannot pend again until it is **completed**. A completion of a source the
//!   context has not enabled, or that was not claimed, is ignored; one that
//!   lands while the line is still asserted pends the source again.
//! * The context's **external line** is high while some source is pending,
//!   enabled and strictly above the threshold; priority 0 never interrupts.

use crate::vlapic::Fault;

/// Where the PLIC window sits on the `virt` machine.
pub const PLIC_DEFAULT_BASE: u64 = 0x0C00_0000;
/// Bytes of the window: priorities, pending, enables and the context pages.
pub const PLIC_WINDOW: u64 = 0x40_0000;
/// Interrupt sources, `1..=SOURCES` (id 0 means "none").
pub const SOURCES: usize = 63;
/// Highest priority (3 bits).
pub const PRIO_MAX: u8 = 7;
/// Contexts a PLIC can have: one per vCPU of the pool.
pub const CONTEXTS: usize = crate::vm::MAX_VCPUS;
/// The virtual interrupt line (`hvip` bit) a context's external line drives:
/// `VSEIP`. The kernel presents it with the vCPU's other lines on every entry
/// ([`Vplic::line`]); a host test holds the number against the CSR file.
pub const EXTERNAL_LINE: u32 = 10;

const PENDING: u64 = 0x00_1000;
const ENABLE: u64 = 0x00_2000;
const ENABLE_STRIDE: u64 = 0x80;
const CONTEXT: u64 = 0x20_0000;
const CONTEXT_STRIDE: u64 = 0x1000;
const CLAIM: u64 = 4;
/// Bit 0 of the 64-bit source bitmaps is source 0, which does not exist.
const VALID: u64 = !1;

/// The external lines that changed in one operation, as masks of contexts
/// (= vCPUs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Change {
    /// Went low to high: pend `VSEIP` on these vCPUs and kick them.
    pub raised: u64,
    /// Went high to low: un-pend it.
    pub lowered: u64,
}

impl Change {
    pub const NONE: Change = Change { raised: 0, lowered: 0 };

    pub fn is_none(&self) -> bool {
        self.raised | self.lowered == 0
    }
}

/// One VM's PLIC.
#[derive(Clone, Debug)]
pub struct Vplic {
    base: u64,
    nctx: usize,
    prio: [u8; SOURCES + 1],
    /// The level each device drives, by source.
    line: u64,
    pending: u64,
    /// Claimed and not completed: the gateway is closed.
    claimed: u64,
    enable: [u64; CONTEXTS],
    threshold: [u8; CONTEXTS],
    /// Sources whose line is an edge, not a level: [`Vplic::pulse`] set them
    /// and the claim (or a completion that pends them again) consumes it.
    pulse: u64,
    /// The external line of each context, as last reported.
    eip: u64,
}

impl Vplic {
    /// A PLIC at `base` for a guest of `contexts` vCPUs (at most
    /// [`CONTEXTS`]), everything disabled and at priority 0 (the reset state).
    pub fn new(base: u64, contexts: usize) -> Vplic {
        Vplic {
            base,
            nctx: contexts.min(CONTEXTS),
            prio: [0; SOURCES + 1],
            line: 0,
            pending: 0,
            claimed: 0,
            enable: [0; CONTEXTS],
            threshold: [0; CONTEXTS],
            pulse: 0,
            eip: 0,
        }
    }

    pub fn mmio_base(&self) -> u64 {
        self.base
    }

    /// Whether context `ctx`'s external line is high.
    pub fn line(&self, ctx: usize) -> bool {
        ctx < CONTEXTS && self.eip >> ctx & 1 != 0
    }

    /// Every context's external line, one bit each.
    pub fn lines(&self) -> u64 {
        self.eip
    }

    /// The source `ctx` would claim now: pending, enabled, above its
    /// threshold; the highest priority, the lowest id among equals.
    fn best(&self, ctx: usize) -> Option<usize> {
        let mut ready = self.pending & self.enable[ctx] & VALID;
        let mut best: Option<(u8, usize)> = None;
        while ready != 0 {
            let s = ready.trailing_zeros() as usize;
            ready &= ready - 1;
            let p = self.prio[s];
            if p > self.threshold[ctx] && best.map_or(true, |(bp, _)| p > bp) {
                best = Some((p, s));
            }
        }
        best.map(|(_, s)| s)
    }

    /// Recompute the external lines and report what moved.
    fn settle(&mut self) -> Change {
        let mut now = 0u64;
        for ctx in 0..self.nctx {
            if self.best(ctx).is_some() {
                now |= 1 << ctx;
            }
        }
        let was = core::mem::replace(&mut self.eip, now);
        Change { raised: now & !was, lowered: was & !now }
    }

    /// The device model drives source `src` to `level`. An asserted line pends
    /// the source unless its gateway is closed (claimed, not completed); a
    /// dropped one un-pends it. Ids outside `1..=63` change nothing.
    pub fn set_irq(&mut self, src: usize, level: bool) -> Change {
        if !(1..=SOURCES).contains(&src) {
            return Change::NONE;
        }
        let bit = 1u64 << src;
        if level {
            self.line |= bit;
            if self.claimed & bit == 0 {
                self.pending |= bit;
            }
        } else {
            self.line &= !bit;
            self.pulse &= !bit;
            self.pending &= !bit;
        }
        self.settle()
    }

    /// The device model reports an **edge** on source `src`: its line went up
    /// and the model will not report it going down (vmmd tells the monitor
    /// only that a device's interrupt is now asserted; the guest's
    /// acknowledgement stays in the device). The edge pends the source once;
    /// the claim consumes it. One that comes while the source is claimed and
    /// not completed is kept and pends it at the completion, so an interrupt
    /// is not lost, and two such collapse into one (a gateway holds one).
    pub fn pulse(&mut self, src: usize) -> Change {
        if !(1..=SOURCES).contains(&src) {
            return Change::NONE;
        }
        self.pulse |= 1 << src;
        self.set_irq(src, true)
    }

    fn claim(&mut self, ctx: usize) -> (u32, Change) {
        let Some(s) = self.best(ctx) else { return (0, Change::NONE) };
        let bit = 1u64 << s;
        self.pending &= !bit;
        self.claimed |= bit;
        // The claim takes the edge that pended it.
        if self.pulse & bit != 0 {
            self.pulse &= !bit;
            self.line &= !bit;
        }
        (s as u32, self.settle())
    }

    fn complete(&mut self, ctx: usize, id: u32) -> Change {
        let id = id as usize;
        if !(1..=SOURCES).contains(&id) {
            return Change::NONE;
        }
        let bit = 1u64 << id;
        if self.enable[ctx] & bit == 0 || self.claimed & bit == 0 {
            return Change::NONE;
        }
        self.claimed &= !bit;
        if self.line & bit != 0 {
            self.pending |= bit;
            // An edge held through the claim is spent by pending the source.
            if self.pulse & bit != 0 {
                self.pulse &= !bit;
                self.line &= !bit;
            }
        }
        self.settle()
    }

    /// The window offset of a 32-bit access at `gpa`.
    fn offset(&self, gpa: u64, size: u8) -> Result<u64, Fault> {
        if gpa < self.base || gpa >= self.base + PLIC_WINDOW || size != 4 || gpa & 3 != 0 {
            return Err(Fault);
        }
        Ok(gpa - self.base)
    }

    /// The context page `off` falls in and the register inside it.
    fn context_reg(&self, off: u64) -> Option<(usize, u64)> {
        let rel = off.checked_sub(CONTEXT)?;
        let ctx = (rel / CONTEXT_STRIDE) as usize;
        (ctx < self.nctx).then_some((ctx, rel % CONTEXT_STRIDE))
    }

    /// The enable word `off` names: context, and the half of the bitmap.
    fn enable_reg(&self, off: u64) -> Option<(usize, u32)> {
        let rel = off.checked_sub(ENABLE)?;
        let ctx = (rel / ENABLE_STRIDE) as usize;
        let word = (rel % ENABLE_STRIDE / 4) as u32;
        (ctx < self.nctx && word < 2).then_some((ctx, word))
    }

    /// The decoded access `a` (`value`: what a store writes) if it falls in
    /// this controller's window: the value a load reads (a store: 0) and the
    /// lines it changed. `None`: not the window. An access the controller
    /// refuses (not one aligned 32-bit word) is a bus that answers 0 and
    /// drops the store, like any hole.
    pub fn serve(&mut self, a: &azos_arch_api::MmioAccess, value: u64) -> Option<(u64, Change)> {
        if a.gpa < self.base || a.gpa - self.base >= PLIC_WINDOW {
            return None;
        }
        Some(if a.write {
            (0, self.mmio_write(a.gpa, a.size, value as u32).unwrap_or(Change::NONE))
        } else {
            self.mmio_read(a.gpa, a.size).map_or((0, Change::NONE), |(v, c)| (v as u64, c))
        })
    }

    /// An `Exit::Mmio` read inside the window (32-bit accesses only). Reading
    /// a context's claim register is a claim, so it can lower a line: the
    /// [`Change`] comes back with the value.
    pub fn mmio_read(&mut self, gpa: u64, size: u8) -> Result<(u32, Change), Fault> {
        let off = self.offset(gpa, size)?;
        let none = |v: u32| Ok((v, Change::NONE));
        match off {
            o if o < PENDING => none(self.prio.get((o / 4) as usize).map_or(0, |&p| p as u32)),
            o if o < PENDING + 8 => none((self.pending >> ((o - PENDING) / 4 * 32)) as u32),
            o if o < CONTEXT => match self.enable_reg(o) {
                Some((c, w)) => none((self.enable[c] >> (w * 32)) as u32),
                None => none(0),
            },
            o => match self.context_reg(o) {
                Some((c, 0)) => none(self.threshold[c] as u32),
                Some((c, CLAIM)) => Ok(self.claim(c)),
                _ => none(0),
            },
        }
    }

    /// An `Exit::Mmio` write inside the window. Priorities, enables and
    /// thresholds can raise or lower a line; a write of the claim register is
    /// a completion.
    pub fn mmio_write(&mut self, gpa: u64, size: u8, val: u32) -> Result<Change, Fault> {
        let off = self.offset(gpa, size)?;
        Ok(match off {
            o if o < PENDING => {
                let s = (o / 4) as usize;
                // Source 0 does not exist: its priority reads and stays 0.
                if (1..=SOURCES).contains(&s) {
                    self.prio[s] = val as u8 & PRIO_MAX;
                    self.settle()
                } else {
                    Change::NONE
                }
            }
            // The pending bits are read-only.
            o if o < ENABLE => Change::NONE,
            o if o < CONTEXT => match self.enable_reg(o) {
                Some((c, w)) => {
                    let keep = !(0xFFFF_FFFFu64 << (w * 32));
                    self.enable[c] = (self.enable[c] & keep | (val as u64) << (w * 32)) & VALID;
                    self.settle()
                }
                None => Change::NONE,
            },
            o => match self.context_reg(o) {
                Some((c, 0)) => {
                    self.threshold[c] = val as u8 & PRIO_MAX;
                    self.settle()
                }
                Some((c, CLAIM)) => self.complete(c, val),
                _ => Change::NONE,
            },
        })
    }
}
