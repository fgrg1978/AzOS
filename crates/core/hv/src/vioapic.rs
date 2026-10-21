// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtual IOAPIC of an x86 guest (Intel 82093AA datasheet, the version
//! 0x20 register set with the EOI register): the redirection table, edge and
//! level lines, and the EOI broadcast that clears a level entry's remote IRR.
//!
//! Like [`crate::vlapic`] it is a pure model. The device model of a pin (the
//! virtual UART, a virtio transport, the HPET) calls [`Vioapic::set_irq`] when
//! its line changes; the exit handler passes an `Exit::Mmio` inside the
//! IOAPIC window to [`Vioapic::mmio_read`] / [`Vioapic::mmio_write`]; and a
//! vLAPIC's [`Effect::Eoi`] comes back through [`deliver_effect`]. Everything
//! the IOAPIC does to the vCPUs is a [`Msgs`] batch of [`Ipi`]s for
//! [`deliver_all`], which routes each to the vLAPICs.

use crate::vlapic::{route, Delivery, Effect, Fault, Ipi, Shorthand, Vlapic};

/// Where the IOAPIC window sits on a PC.
pub const IOAPIC_DEFAULT_BASE: u64 = 0xFEC0_0000;
/// Bytes of the window: `IOREGSEL`, `IOWIN` and the EOI register.
pub const IOAPIC_WINDOW: u64 = 0x1000;
/// Interrupt inputs.
pub const PINS: usize = 24;

const REG_SEL: u64 = 0x00;
const REG_WIN: u64 = 0x10;
const REG_EOI: u64 = 0x40;

/// `IOAPICVER`: version 0x20 (the EOI register exists), the highest
/// redirection entry in bits 23:16.
const VERSION: u32 = 0x20 | (PINS as u32 - 1) << 16;

const RTE_LOGICAL: u64 = 1 << 11;
const RTE_LOW_POLARITY: u64 = 1 << 13;
const RTE_LEVEL: u64 = 1 << 15;
const RTE_MASKED: u64 = 1 << 16;
const RTE_REMOTE_IRR: u64 = 1 << 14;
/// Writable bits of the low dword: vector, delivery mode, destination mode,
/// polarity, trigger mode, mask. Delivery status and remote IRR are read-only.
const RTE_LOW_WRITABLE: u64 = 0xFF | 7 << 8 | RTE_LOGICAL | RTE_LOW_POLARITY | RTE_LEVEL | RTE_MASKED;

const NO_MSG: Ipi = Ipi {
    vector: 0,
    delivery: Delivery::Fixed,
    logical: false,
    level: false,
    assert: true,
    dest: 0,
    broadcast: false,
    shorthand: Shorthand::None,
};

/// The messages one IOAPIC operation produced: at most one per pin.
#[derive(Clone, Copy, Debug)]
pub struct Msgs {
    buf: [Ipi; PINS],
    n: usize,
}

impl Msgs {
    pub const fn new() -> Msgs {
        Msgs { buf: [NO_MSG; PINS], n: 0 }
    }

    fn push(&mut self, m: Ipi) {
        // One message per pin per operation: a batch cannot overflow.
        self.buf[self.n] = m;
        self.n += 1;
    }

    pub fn as_slice(&self) -> &[Ipi] {
        &self.buf[..self.n]
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

impl PartialEq for Msgs {
    fn eq(&self, o: &Msgs) -> bool {
        self.as_slice() == o.as_slice()
    }
}

impl Eq for Msgs {}

impl Default for Msgs {
    fn default() -> Msgs {
        Msgs::new()
    }
}

/// One VM's IOAPIC.
#[derive(Clone, Debug)]
pub struct Vioapic {
    base: u64,
    id: u8,
    sel: u8,
    rte: [u64; PINS],
    /// The physical level of each input, before polarity.
    line: [bool; PINS],
    /// Remote IRR of each level-triggered entry: delivered, not yet EOI'd.
    rirr: u32,
    /// Pins a device model raised once ([`Vioapic::pulse`]) on a level entry
    /// and the entry has not delivered yet: the line counts as active until
    /// the message goes out, and no longer.
    latched: u32,
}

impl Vioapic {
    /// An IOAPIC at `base` with every entry masked (the reset state).
    pub fn new(id: u8, base: u64) -> Vioapic {
        Vioapic { base, id: id & 0xF, sel: 0, rte: [RTE_MASKED; PINS], line: [false; PINS], rirr: 0, latched: 0 }
    }

    pub fn mmio_base(&self) -> u64 {
        self.base
    }

    fn masked(&self, pin: usize) -> bool {
        self.rte[pin] & RTE_MASKED != 0
    }

    fn level_triggered(&self, pin: usize) -> bool {
        self.rte[pin] & RTE_LEVEL != 0
    }

    /// Whether the line is in its active state (polarity applied).
    fn asserted(&self, pin: usize) -> bool {
        self.line[pin] ^ (self.rte[pin] & RTE_LOW_POLARITY != 0) || self.latched >> pin & 1 != 0
    }

    /// Send the entry's message; a level-triggered one stays outstanding
    /// (remote IRR) until its vector's EOI comes back.
    fn fire(&mut self, pin: usize, out: &mut Msgs) {
        let e = self.rte[pin];
        let Some(delivery) = Delivery::from_bits((e >> 8 & 7) as u32) else { return };
        let logical = e & RTE_LOGICAL != 0;
        let dest = (e >> 56) as u32;
        let level = e & RTE_LEVEL != 0;
        self.latched &= !(1 << pin);
        if level && matches!(delivery, Delivery::Fixed | Delivery::LowestPriority) {
            self.rirr |= 1 << pin;
        }
        out.push(Ipi {
            vector: e as u8,
            delivery,
            logical,
            level,
            assert: true,
            dest,
            broadcast: !logical && dest == 0xFF,
            shorthand: Shorthand::None,
        });
    }

    /// The device model drives input `pin` to `level`. An edge entry sends on
    /// the line going active; a level entry sends while the line is active and
    /// no earlier message is outstanding. A masked entry sends nothing (an
    /// edge on it is lost; a level one is sent when unmasked).
    pub fn set_irq(&mut self, pin: usize, level: bool) -> Msgs {
        let mut out = Msgs::new();
        if pin >= PINS {
            return out;
        }
        let was = self.asserted(pin);
        self.line[pin] = level;
        let now = self.asserted(pin);
        if self.masked(pin) {
            return out;
        }
        if self.level_triggered(pin) {
            if now && self.rirr >> pin & 1 == 0 {
                self.fire(pin, &mut out);
            }
        } else if now && !was {
            self.fire(pin, &mut out);
        }
        out
    }

    /// The device model raises `pin` once, with no line to lower afterwards
    /// (an interrupt event the monitor is handed, `Vcpu::inject`). An edge
    /// entry sees one edge. A level entry sees the line active until its
    /// message goes out: at once, or when the guest unmasks it, or when the
    /// EOI of the message before it releases it, so two events that arrive
    /// before the guest's EOI are one interrupt and none is lost.
    pub fn pulse(&mut self, pin: usize) -> Msgs {
        let mut out = Msgs::new();
        if pin >= PINS {
            return out;
        }
        if self.level_triggered(pin) {
            self.latched |= 1 << pin;
            if !self.masked(pin) && self.rirr >> pin & 1 == 0 {
                self.fire(pin, &mut out);
            }
            return out;
        }
        out = self.set_irq(pin, true);
        self.set_irq(pin, false);
        out
    }

    /// A vLAPIC's EOI of a level-triggered `vector` reached the IOAPIC: the
    /// entries carrying it are no longer outstanding, and one whose line is
    /// still active sends again.
    pub fn eoi(&mut self, vector: u8) -> Msgs {
        let mut out = Msgs::new();
        for pin in 0..PINS {
            if self.rirr >> pin & 1 != 0 && self.rte[pin] as u8 == vector {
                self.rirr &= !(1 << pin);
                if self.level_triggered(pin) && !self.masked(pin) && self.asserted(pin) {
                    self.fire(pin, &mut out);
                }
            }
        }
        out
    }

    // ── indirect registers ─────────────────────────────────────────────

    fn reg_read(&self, idx: u8) -> u32 {
        match idx {
            0x00 => (self.id as u32) << 24,
            0x01 => VERSION,
            // Arbitration ID.
            0x02 => (self.id as u32) << 24,
            0x10..=0x3F => {
                let pin = (idx as usize - 0x10) / 2;
                if pin >= PINS {
                    return 0;
                }
                let e = self.rte[pin] | if self.rirr >> pin & 1 != 0 { RTE_REMOTE_IRR } else { 0 };
                if idx & 1 == 0 { e as u32 } else { (e >> 32) as u32 }
            }
            _ => 0,
        }
    }

    fn reg_write(&mut self, idx: u8, val: u32) -> Msgs {
        let mut out = Msgs::new();
        match idx {
            0x00 => self.id = (val >> 24) as u8 & 0xF,
            0x10..=0x3F => {
                let pin = (idx as usize - 0x10) / 2;
                if pin >= PINS {
                    return out;
                }
                if idx & 1 == 0 {
                    self.rte[pin] = self.rte[pin] & !0xFFFF_FFFF | val as u64 & RTE_LOW_WRITABLE;
                    if !self.level_triggered(pin) {
                        // Becoming edge-triggered clears an outstanding level.
                        self.rirr &= !(1 << pin);
                        self.latched &= !(1 << pin);
                    } else if !self.masked(pin) && self.asserted(pin) && self.rirr >> pin & 1 == 0 {
                        // Unmasking a level entry whose line is active.
                        self.fire(pin, &mut out);
                    }
                } else {
                    self.rte[pin] = self.rte[pin] & 0x00FF_FFFF_FFFF_FFFF | (val as u64 & 0xFF00_0000) << 32;
                }
            }
            // Version and arbitration are read-only.
            _ => {}
        }
        out
    }

    fn offset(&self, gpa: u64, size: u8) -> Result<u64, Fault> {
        if gpa < self.base || gpa >= self.base + IOAPIC_WINDOW || size != 4 {
            return Err(Fault);
        }
        Ok(gpa - self.base)
    }

    /// An `Exit::Mmio` read inside the window (32-bit accesses only).
    pub fn mmio_read(&self, gpa: u64, size: u8) -> Result<u32, Fault> {
        Ok(match self.offset(gpa, size)? {
            REG_SEL => self.sel as u32,
            REG_WIN => self.reg_read(self.sel),
            _ => 0,
        })
    }

    /// An `Exit::Mmio` write inside the window. A write of an entry can send
    /// (an unmasked level line that is active): the messages come back.
    pub fn mmio_write(&mut self, gpa: u64, size: u8, val: u32) -> Result<Msgs, Fault> {
        Ok(match self.offset(gpa, size)? {
            REG_SEL => {
                self.sel = val as u8;
                Msgs::new()
            }
            REG_WIN => self.reg_write(self.sel, val),
            REG_EOI => self.eoi(val as u8),
            _ => Msgs::new(),
        })
    }
}

/// Route every message of `msgs` to the VM's vCPUs; the mask of vCPUs that
/// received any.
pub fn deliver_all(apics: &mut [Vlapic], msgs: &Msgs) -> u64 {
    msgs.as_slice().iter().fold(0, |hit, m| hit | route(apics, None, m))
}

/// Raise the interrupt lines of `lines` (bit `n`, pin `n`, as
/// `GuestCtx::irqs` carries them) once each, and route what the IOAPIC sends
/// to the vCPUs. The mask of vCPUs that received a message.
pub fn pulse_lines(apics: &mut [Vlapic], ioapic: &mut Vioapic, lines: u64) -> u64 {
    let mut hit = 0;
    for pin in (0..PINS).filter(|&p| lines >> p & 1 != 0) {
        let msgs = ioapic.pulse(pin);
        hit |= deliver_all(apics, &msgs);
    }
    hit
}

/// Apply what a write to vCPU `src`'s APIC asked of the VM: send an IPI, or
/// broadcast a level EOI to the IOAPIC (and send what that releases).
/// `Remapped` is the handler's own business (the window moved) and does
/// nothing here. The mask of vCPUs that received a message.
pub fn deliver_effect(apics: &mut [Vlapic], ioapic: &mut Vioapic, src: usize, e: Effect) -> u64 {
    match e {
        Effect::None | Effect::Remapped => 0,
        Effect::Ipi(ipi) => route(apics, Some(src), &ipi),
        Effect::Eoi(v) => {
            let msgs = ioapic.eoi(v);
            deliver_all(apics, &msgs)
        }
    }
}
