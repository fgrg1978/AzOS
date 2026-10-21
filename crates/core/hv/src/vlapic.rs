// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtual local APIC of an x86 guest vCPU (Intel SDM vol. 3 ch. 12, AMD
//! APM vol. 2 ch. 16): its register file, the interrupt priority rules, the
//! timer and the IPI send, as a pure model.
//!
//! The model touches nothing but itself. The SVM / VMX exit handler hands it
//! what it decoded and applies what it returns:
//!
//! * a trapped `RDMSR` / `WRMSR` of the x2APIC range (`0x800..0x900`),
//!   `IA32_APIC_BASE` or `IA32_TSC_DEADLINE` -> [`Vlapic::msr_read`] /
//!   [`Vlapic::msr_write`]; `Err(Fault)` is a `#GP(0)` for the guest;
//! * an `Exit::Mmio` inside the xAPIC page -> [`Vlapic::mmio_read`] /
//!   [`Vlapic::mmio_write`] (only while the guest has the APIC in xAPIC mode);
//! * the guest-entry path asks [`Vlapic::pending`] for the vector to inject
//!   (event injection into the VMCB / VMCS) when the guest can take it, and
//!   calls [`Vlapic::ack`] once injected, which moves it from the IRR to the
//!   ISR; [`Vlapic::take_event`] yields NMI / SMI / INIT / startup / ExtINT;
//! * time is the guest's TSC, passed in by the caller. The host arms one
//!   timer for [`Vlapic::next_deadline`] and calls [`Vlapic::tick`] when it
//!   fires, so a vCPU with no armed guest timer costs the host nothing.
//!
//! What a write sends to *other* vCPUs or to the IOAPIC comes back as an
//! [`Effect`]; [`route`] delivers an [`Ipi`] to the vCPUs of a VM and
//! `vioapic::deliver` applies any effect, so the model never reaches into a
//! sibling.
//!
//! # Simplifications (each is an SDM behavior this model leaves out)
//!
//! * delivery status (ICR bit 12, LVT bit 12) always reads idle: a send is
//!   instantaneous;
//! * no focus-processor checking, no EOI-broadcast suppression, no interrupt
//!   remapping: the IOAPIC addresses vCPUs by 8-bit destination;
//! * a periodic timer that missed periods fires once, not once per period.

/// `IA32_APIC_BASE`.
pub const MSR_APIC_BASE: u32 = 0x1B;
/// `IA32_TSC_DEADLINE`.
pub const MSR_TSC_DEADLINE: u32 = 0x6E0;
/// First MSR of the x2APIC register window; MSR `0x800 + (offset >> 4)`.
pub const MSR_X2APIC_FIRST: u32 = 0x800;
/// One past the last MSR of the x2APIC window.
pub const MSR_X2APIC_END: u32 = 0x900;
/// Where the xAPIC page sits after reset.
pub const APIC_DEFAULT_BASE: u64 = 0xFEE0_0000;
/// Bytes of the xAPIC register page.
pub const APIC_PAGE: u64 = 0x1000;

const BASE_BSP: u64 = 1 << 8;
const BASE_EXTD: u64 = 1 << 10;
const BASE_EN: u64 = 1 << 11;
/// Bits 47:12 of `IA32_APIC_BASE`.
const BASE_ADDR: u64 = 0x0000_FFFF_FFFF_F000;

const SVR_ENABLE: u32 = 1 << 8;
const LVT_MASK: u32 = 1 << 16;

/// LVT entries: CMCI, timer, thermal, performance counter, LINT0, LINT1, error.
pub const LVT_COUNT: usize = 7;
const LVT_TIMER: usize = 1;
const LVT_ERROR: usize = 6;
/// `VERSION`: integrated APIC version 0x14, `LVT_COUNT - 1` in bits 23:16.
const VERSION: u32 = 0x14 | ((LVT_COUNT as u32 - 1) << 16);

// Error status bits.
const ESR_SEND_ILLEGAL_VECTOR: u32 = 1 << 5;
const ESR_RECV_ILLEGAL_VECTOR: u32 = 1 << 6;

// LVT timer mode (bits 18:17).
const TIMER_ONE_SHOT: u32 = 0;
const TIMER_PERIODIC: u32 = 1;
const TIMER_DEADLINE: u32 = 2;

/// A guest access the model refuses: the exit handler injects `#GP(0)` (an
/// MSR access) or drops the access (an MMIO one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault;

/// How the guest has the APIC configured (`IA32_APIC_BASE` bits 11:10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Globally disabled: neither the page nor the MSRs answer.
    Off,
    /// The memory-mapped page.
    XApic,
    /// The MSR window.
    X2Apic,
}

/// The delivery modes an ICR, an LVT entry or an IOAPIC entry can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Delivery {
    Fixed = 0,
    LowestPriority = 1,
    Smi = 2,
    Nmi = 4,
    Init = 5,
    Startup = 6,
    ExtInt = 7,
}

impl Delivery {
    pub const fn from_bits(b: u32) -> Option<Delivery> {
        Some(match b {
            0 => Delivery::Fixed,
            1 => Delivery::LowestPriority,
            2 => Delivery::Smi,
            4 => Delivery::Nmi,
            5 => Delivery::Init,
            6 => Delivery::Startup,
            7 => Delivery::ExtInt,
            _ => return None,
        })
    }
}

/// The ICR destination shorthand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shorthand {
    None,
    SelfOnly,
    All,
    AllButSelf,
}

/// One interrupt message on the (virtual) APIC bus: an ICR send or an IOAPIC
/// redirection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipi {
    pub vector: u8,
    pub delivery: Delivery,
    /// Destination mode: logical (true) or physical.
    pub logical: bool,
    /// Trigger mode: level (true) or edge. A level message sets the target's
    /// TMR bit, so its EOI is broadcast to the IOAPIC.
    pub level: bool,
    /// Level assert (ICR bit 14); false only for an INIT level de-assert.
    pub assert: bool,
    pub dest: u32,
    /// Every APIC: physical `0xFF` (xAPIC format) / `0xFFFF_FFFF` (x2APIC).
    pub broadcast: bool,
    pub shorthand: Shorthand,
}

/// What a register write asks of the rest of the VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    /// Send this message ([`route`]).
    Ipi(Ipi),
    /// EOI of a level-triggered vector: broadcast it to the IOAPIC.
    Eoi(u8),
    /// The APIC mode or the page address changed: the handler re-points the
    /// xAPIC page window and the MSR intercept.
    Remapped,
}

/// A non-vector event for the vCPU, in the order [`Vlapic::take_event`]
/// returns them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Init,
    Startup(u8),
    Smi,
    Nmi,
    ExtInt,
}

/// The local vector table entries a device model or the platform raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Lvt {
    Cmci = 0,
    Timer = 1,
    Thermal = 2,
    Perf = 3,
    Lint0 = 4,
    Lint1 = 5,
    Error = 6,
}

const EV_INIT: u8 = 1;
const EV_SIPI: u8 = 2;
const EV_SMI: u8 = 4;
const EV_NMI: u8 = 8;
const EV_EXTINT: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Timer {
    Off,
    /// One-shot or periodic: counting since `start`, next expiry at `expiry`
    /// (guest TSC).
    Count { start: u64, expiry: u64 },
    /// TSC-deadline: fire when the guest TSC reaches this value.
    Deadline(u64),
}

/// One vCPU's local APIC.
#[derive(Clone, Debug)]
pub struct Vlapic {
    id: u32,
    base: u64,
    tpr: u8,
    ldr: u32,
    dfr: u32,
    svr: u32,
    irr: [u32; 8],
    isr: [u32; 8],
    tmr: [u32; 8],
    lvt: [u32; LVT_COUNT],
    esr: u32,
    esr_pending: u32,
    icr: u64,
    icr_hi: u32,
    divide: u32,
    initial: u32,
    timer: Timer,
    /// Guest TSC cycles per tick of the undivided APIC timer clock.
    tsc_per_tick: u64,
    events: u8,
    sipi_vector: u8,
}

/// Highest set bit of a 256-bit register, as a vector.
fn highest(bits: &[u32; 8]) -> Option<u8> {
    for w in (0..8).rev() {
        if bits[w] != 0 {
            return Some((w as u32 * 32 + 31 - bits[w].leading_zeros()) as u8);
        }
    }
    None
}

fn set_bit(bits: &mut [u32; 8], v: u8, on: bool) {
    let (w, b) = (v as usize / 32, v as u32 % 32);
    if on {
        bits[w] |= 1 << b;
    } else {
        bits[w] &= !(1 << b);
    }
}

fn get_bit(bits: &[u32; 8], v: u8) -> bool {
    bits[v as usize / 32] >> (v as u32 % 32) & 1 != 0
}

/// The xAPIC offset an LVT entry lives at.
const fn lvt_offset(i: usize) -> u16 {
    if i == 0 { 0x2F0 } else { 0x310 + 0x10 * i as u16 }
}

fn lvt_index(off: u16) -> Option<usize> {
    (0..LVT_COUNT).find(|&i| lvt_offset(i) == off)
}

impl Vlapic {
    /// A vCPU's APIC at power-on: enabled in xAPIC mode at the default
    /// address, software-disabled, every LVT entry masked. `tsc_per_tick` is
    /// the guest TSC cycles per tick of the APIC timer's undivided clock (TSC
    /// frequency over the bus / crystal frequency CPUID leaf 0x15 reports).
    pub fn new(id: u32, bsp: bool, tsc_per_tick: u64) -> Vlapic {
        let mut a = Vlapic {
            id,
            base: APIC_DEFAULT_BASE | BASE_EN | if bsp { BASE_BSP } else { 0 },
            tpr: 0,
            ldr: 0,
            dfr: !0,
            svr: 0xFF,
            irr: [0; 8],
            isr: [0; 8],
            tmr: [0; 8],
            lvt: [LVT_MASK; LVT_COUNT],
            esr: 0,
            esr_pending: 0,
            icr: 0,
            icr_hi: 0,
            divide: 0,
            initial: 0,
            timer: Timer::Off,
            tsc_per_tick: tsc_per_tick.max(1),
            events: 0,
            sipi_vector: 0,
        };
        a.init_reset();
        a
    }

    /// The register state an INIT leaves (everything but the ID and
    /// `IA32_APIC_BASE`): the handler calls it after taking [`Event::Init`].
    pub fn init_reset(&mut self) {
        self.tpr = 0;
        self.ldr = 0;
        self.dfr = !0;
        self.svr = 0xFF;
        self.irr = [0; 8];
        self.isr = [0; 8];
        self.tmr = [0; 8];
        self.lvt = [LVT_MASK; LVT_COUNT];
        self.esr = 0;
        self.esr_pending = 0;
        self.icr = 0;
        self.icr_hi = 0;
        self.divide = 0;
        self.initial = 0;
        self.timer = Timer::Off;
        // A startup IPI that is already queued came after the INIT in the
        // protocol (INIT, wait, SIPI): the vCPU thread that handles the INIT
        // may run only after both were sent, and the SIPI must survive it.
        self.events &= EV_SIPI;
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn mode(&self) -> Mode {
        match (self.base & BASE_EN != 0, self.base & BASE_EXTD != 0) {
            (false, _) => Mode::Off,
            (true, false) => Mode::XApic,
            (true, true) => Mode::X2Apic,
        }
    }

    /// Guest-physical address of the xAPIC page.
    pub fn mmio_base(&self) -> u64 {
        self.base & BASE_ADDR
    }

    /// The APIC takes interrupts: globally and software enabled.
    fn enabled(&self) -> bool {
        self.mode() != Mode::Off && self.svr & SVR_ENABLE != 0
    }

    // ── priority ───────────────────────────────────────────────────────

    /// Processor priority: the higher of the task priority and the in-service
    /// class.
    pub fn ppr(&self) -> u8 {
        let isrv = highest(&self.isr).unwrap_or(0);
        if self.tpr & 0xF0 >= isrv & 0xF0 { self.tpr } else { isrv & 0xF0 }
    }

    /// The vector to inject next: the highest requested one whose priority
    /// class beats the processor priority. The guest-entry path injects it
    /// when the guest can take an interrupt, then calls [`Vlapic::ack`].
    pub fn pending(&self) -> Option<u8> {
        let v = highest(&self.irr)?;
        if v & 0xF0 > self.ppr() & 0xF0 { Some(v) } else { None }
    }

    /// The vector was injected: requested -> in service.
    pub fn ack(&mut self) -> Option<u8> {
        let v = self.pending()?;
        set_bit(&mut self.irr, v, false);
        set_bit(&mut self.isr, v, true);
        Some(v)
    }

    /// Whether any vector is requested, deliverable or not: the vCPU must not
    /// sleep in `hlt` while this holds.
    pub fn has_work(&self) -> bool {
        self.irr != [0; 8] || self.events != 0
    }

    fn eoi(&mut self) -> Effect {
        let Some(v) = highest(&self.isr) else { return Effect::None };
        set_bit(&mut self.isr, v, false);
        if get_bit(&self.tmr, v) { Effect::Eoi(v) } else { Effect::None }
    }

    fn error(&mut self, bits: u32) {
        self.esr_pending |= bits;
        self.raise(Lvt::Error);
    }

    /// Request `vector` (fixed delivery); `level` marks it level-triggered.
    /// `report`: an illegal vector raises the error LVT (off for the error
    /// LVT's own message, which must not recurse).
    fn accept(&mut self, vector: u8, level: bool, report: bool) {
        if !self.enabled() {
            return;
        }
        if vector < 16 {
            self.esr_pending |= ESR_RECV_ILLEGAL_VECTOR;
            if report {
                self.raise(Lvt::Error);
            }
            return;
        }
        set_bit(&mut self.irr, vector, true);
        set_bit(&mut self.tmr, vector, level);
    }

    /// A message addressed to this APIC arrives.
    pub fn deliver(&mut self, ipi: &Ipi) {
        self.deliver_inner(ipi, true);
    }

    fn deliver_inner(&mut self, ipi: &Ipi, report: bool) {
        if self.mode() == Mode::Off {
            return;
        }
        match ipi.delivery {
            Delivery::Fixed | Delivery::LowestPriority => self.accept(ipi.vector, ipi.level, report),
            Delivery::Smi => self.events |= EV_SMI,
            Delivery::Nmi => self.events |= EV_NMI,
            Delivery::Init => {
                // A level de-assert INIT is only a synchronization message.
                if !(ipi.level && !ipi.assert) {
                    self.events |= EV_INIT;
                }
            }
            Delivery::Startup => {
                self.events |= EV_SIPI;
                self.sipi_vector = ipi.vector;
            }
            Delivery::ExtInt => self.events |= EV_EXTINT,
        }
    }

    /// The next non-vector event for the vCPU, in the order INIT, startup,
    /// SMI, NMI, ExtINT.
    pub fn take_event(&mut self) -> Option<Event> {
        for (bit, ev) in [
            (EV_INIT, Event::Init),
            (EV_SIPI, Event::Startup(self.sipi_vector)),
            (EV_SMI, Event::Smi),
            (EV_NMI, Event::Nmi),
            (EV_EXTINT, Event::ExtInt),
        ] {
            if self.events & bit != 0 {
                self.events &= !bit;
                return Some(ev);
            }
        }
        None
    }

    /// Raise a local vector table entry: a device model wiring LINT0 / LINT1,
    /// the performance counters, a thermal or corrected-error event. A
    /// masked entry (or a software-disabled APIC) swallows it.
    pub fn raise(&mut self, which: Lvt) {
        let e = self.lvt[which as usize];
        if e & LVT_MASK != 0 || !self.enabled() {
            return;
        }
        let ipi = Ipi {
            vector: e as u8,
            // The timer and error entries have no delivery mode field.
            delivery: if matches!(which, Lvt::Timer | Lvt::Error) {
                Delivery::Fixed
            } else {
                Delivery::from_bits(e >> 8 & 7).unwrap_or(Delivery::Fixed)
            },
            logical: false,
            level: false,
            assert: true,
            dest: self.id,
            broadcast: false,
            shorthand: Shorthand::SelfOnly,
        };
        self.deliver_inner(&ipi, which != Lvt::Error);
    }

    // ── destination matching ───────────────────────────────────────────

    /// Whether a message with a destination field (no shorthand) is for this
    /// APIC.
    pub fn accepts(&self, ipi: &Ipi) -> bool {
        let m = self.mode();
        if m == Mode::Off {
            return false;
        }
        if ipi.broadcast {
            return true;
        }
        if !ipi.logical {
            return match m {
                Mode::X2Apic => ipi.dest == self.id,
                _ => ipi.dest == self.id & 0xFF,
            };
        }
        if m == Mode::X2Apic {
            let ldr = self.x2_ldr();
            return ipi.dest >> 16 == ldr >> 16 && ipi.dest & ldr & 0xFFFF != 0;
        }
        let (mda, mine) = (ipi.dest as u8, (self.ldr >> 24) as u8);
        if self.dfr >> 28 == 0xF {
            mda & mine != 0
        } else {
            (mda >> 4 == mine >> 4 || mda >> 4 == 0xF) && mda & mine & 0xF != 0
        }
    }

    /// The x2APIC logical ID: cluster in the high half, a one-hot position in
    /// the low half, both from the APIC ID.
    fn x2_ldr(&self) -> u32 {
        (self.id >> 4) << 16 | 1 << (self.id & 15)
    }

    // ── timer ──────────────────────────────────────────────────────────

    fn timer_mode(&self) -> u32 {
        self.lvt[LVT_TIMER] >> 17 & 3
    }

    /// Divisor of the timer clock: the divide configuration register's
    /// encoding (bit 3 and bits 1:0) is 2, 4, 8, 16, 32, 64, 128, 1.
    fn divisor(&self) -> u64 {
        let d = (self.divide & 3) | (self.divide >> 3 & 1) << 2;
        if d == 7 { 1 } else { 2 << d }
    }

    /// Guest TSC cycles per counted tick. Every TSC computation below
    /// saturates: the guest owns its TSC (WRMSR), so `now` can be anything.
    fn tick_len(&self) -> u64 {
        self.divisor().saturating_mul(self.tsc_per_tick)
    }

    fn period(&self) -> u64 {
        (self.initial as u64).saturating_mul(self.tick_len())
    }

    fn current_count(&self, now: u64) -> u32 {
        let Timer::Count { start, expiry } = self.timer else { return 0 };
        if now >= expiry && self.timer_mode() == TIMER_ONE_SHOT {
            return 0;
        }
        let elapsed = now.saturating_sub(start) / self.tick_len();
        match self.timer_mode() {
            TIMER_PERIODIC => (self.initial as u64 - elapsed % self.initial as u64) as u32,
            _ => (self.initial as u64).saturating_sub(elapsed) as u32,
        }
    }

    /// The guest TSC value at which [`Vlapic::tick`] next has something to
    /// do, if the guest has an unmasked timer armed. The host arms one timer
    /// for it.
    pub fn next_deadline(&self) -> Option<u64> {
        if self.lvt[LVT_TIMER] & LVT_MASK != 0 {
            return None;
        }
        match self.timer {
            Timer::Off => None,
            Timer::Count { expiry, .. } => Some(expiry),
            Timer::Deadline(d) => Some(d),
        }
    }

    /// Fire the timer if its time has come (guest TSC `now`).
    pub fn tick(&mut self, now: u64) {
        match self.timer {
            Timer::Off => {}
            Timer::Deadline(d) => {
                if now >= d {
                    self.timer = Timer::Off;
                    self.raise(Lvt::Timer);
                }
            }
            Timer::Count { expiry, .. } => {
                if now < expiry {
                    return;
                }
                if self.timer_mode() == TIMER_PERIODIC && self.period() != 0 {
                    // Skip the periods that passed unobserved: one interrupt.
                    let p = self.period();
                    let missed = ((now - expiry) / p).saturating_add(1);
                    let next = expiry.saturating_add(missed.saturating_mul(p));
                    self.timer = Timer::Count { start: next.saturating_sub(p), expiry: next };
                } else {
                    self.timer = Timer::Off;
                }
                self.raise(Lvt::Timer);
            }
        }
    }

    fn arm_count(&mut self, now: u64) {
        self.timer = if self.initial == 0 {
            Timer::Off
        } else {
            Timer::Count { start: now, expiry: now.saturating_add(self.period()) }
        };
    }

    // ── MSR interface ──────────────────────────────────────────────────

    /// A trapped `RDMSR` of an MSR this model serves.
    pub fn msr_read(&mut self, msr: u32, now: u64) -> Result<u64, Fault> {
        match msr {
            MSR_APIC_BASE => Ok(self.base),
            MSR_TSC_DEADLINE => Ok(match self.timer {
                Timer::Deadline(d) if self.timer_mode() == TIMER_DEADLINE => d,
                _ => 0,
            }),
            MSR_X2APIC_FIRST..MSR_X2APIC_END if self.mode() == Mode::X2Apic => {
                self.read_reg(((msr - MSR_X2APIC_FIRST) << 4) as u16, true, now)
            }
            _ => Err(Fault),
        }
    }

    /// A trapped `WRMSR`.
    pub fn msr_write(&mut self, msr: u32, val: u64, now: u64) -> Result<Effect, Fault> {
        match msr {
            MSR_APIC_BASE => self.write_base(val),
            MSR_TSC_DEADLINE => {
                if self.timer_mode() == TIMER_DEADLINE {
                    self.timer = if val == 0 { Timer::Off } else { Timer::Deadline(val) };
                    // A deadline already in the past fires at once.
                    self.tick(now);
                }
                Ok(Effect::None)
            }
            MSR_X2APIC_FIRST..MSR_X2APIC_END if self.mode() == Mode::X2Apic => {
                self.write_reg(((msr - MSR_X2APIC_FIRST) << 4) as u16, true, val, now)
            }
            _ => Err(Fault),
        }
    }

    fn write_base(&mut self, val: u64) -> Result<Effect, Fault> {
        // Reserved: bits 7:0, 9, and everything above the address field.
        if val & !(BASE_ADDR | BASE_BSP | BASE_EXTD | BASE_EN) != 0 {
            return Err(Fault);
        }
        let (en, extd) = (val & BASE_EN != 0, val & BASE_EXTD != 0);
        let old = self.mode();
        let new = match (en, extd) {
            (false, true) => return Err(Fault),
            (false, false) => Mode::Off,
            (true, false) => Mode::XApic,
            (true, true) => Mode::X2Apic,
        };
        // x2APIC is entered from xAPIC and left through disabled only.
        match (old, new) {
            (Mode::Off, Mode::X2Apic) | (Mode::X2Apic, Mode::XApic) => return Err(Fault),
            _ => {}
        }
        let moved = (val ^ self.base) & (BASE_ADDR | BASE_EN | BASE_EXTD) != 0;
        // The BSP flag is not the guest's to change.
        self.base = val & !BASE_BSP | self.base & BASE_BSP;
        Ok(if moved { Effect::Remapped } else { Effect::None })
    }

    // ── xAPIC page ─────────────────────────────────────────────────────

    fn page_offset(&self, gpa: u64, size: u8) -> Result<u16, Fault> {
        let base = self.mmio_base();
        if self.mode() != Mode::XApic || gpa < base || gpa >= base + APIC_PAGE {
            return Err(Fault);
        }
        let off = gpa - base;
        // Registers are 32 bits wide on 16-byte boundaries.
        if size != 4 || off & 0xF != 0 {
            return Err(Fault);
        }
        Ok(off as u16)
    }

    /// An `Exit::Mmio` read inside the xAPIC page.
    pub fn mmio_read(&mut self, gpa: u64, size: u8, now: u64) -> Result<u32, Fault> {
        let off = self.page_offset(gpa, size)?;
        Ok(self.read_reg(off, false, now)? as u32)
    }

    /// An `Exit::Mmio` write inside the xAPIC page.
    pub fn mmio_write(&mut self, gpa: u64, size: u8, val: u32, now: u64) -> Result<Effect, Fault> {
        let off = self.page_offset(gpa, size)?;
        self.write_reg(off, false, val as u64, now)
    }

    // ── the register file, by xAPIC offset ─────────────────────────────

    fn read_reg(&mut self, off: u16, x2: bool, now: u64) -> Result<u64, Fault> {
        Ok(match off {
            0x20 => if x2 { self.id as u64 } else { (self.id as u64 & 0xFF) << 24 },
            0x30 => VERSION as u64,
            0x80 => self.tpr as u64,
            0x90 if !x2 => self.ppr() as u64,
            0xA0 => self.ppr() as u64,
            0xD0 => if x2 { self.x2_ldr() as u64 } else { self.ldr as u64 },
            0xE0 if !x2 => self.dfr as u64,
            0xF0 => self.svr as u64,
            0x100..=0x170 => self.isr[(off as usize - 0x100) >> 4] as u64,
            0x180..=0x1F0 => self.tmr[(off as usize - 0x180) >> 4] as u64,
            0x200..=0x270 => self.irr[(off as usize - 0x200) >> 4] as u64,
            0x280 => self.esr as u64,
            0x300 => if x2 { self.icr } else { self.icr & 0xFFFF_EFFF },
            0x310 if !x2 => self.icr_hi as u64,
            0x380 => self.initial as u64,
            0x390 => self.current_count(now) as u64,
            0x3E0 => self.divide as u64,
            _ => {
                if let Some(i) = lvt_index(off) {
                    self.lvt[i] as u64
                } else if x2 {
                    // Write-only (EOI, self IPI), absent (DFR, ICR high, APR)
                    // or reserved in x2APIC mode.
                    return Err(Fault);
                } else {
                    0
                }
            }
        })
    }

    fn write_reg(&mut self, off: u16, x2: bool, val: u64, now: u64) -> Result<Effect, Fault> {
        let v32 = val as u32;
        match off {
            0x80 => {
                if x2 && val > 0xFF {
                    return Err(Fault);
                }
                self.tpr = val as u8;
            }
            0xB0 => {
                if x2 && val != 0 {
                    return Err(Fault);
                }
                return Ok(self.eoi());
            }
            0xD0 if !x2 => self.ldr = v32 & 0xFF00_0000,
            0xE0 if !x2 => self.dfr = 0x0FFF_FFFF | (v32 & 0xF000_0000),
            0xF0 => {
                self.svr = v32 & 0x1FF;
                if self.svr & SVR_ENABLE == 0 {
                    // Software-disabling the APIC masks every LVT entry, and
                    // they stay masked until it is enabled and rewritten.
                    for e in self.lvt.iter_mut() {
                        *e |= LVT_MASK;
                    }
                }
            }
            0x280 => {
                if x2 && val != 0 {
                    return Err(Fault);
                }
                // The write latches the errors seen since the last one.
                self.esr = self.esr_pending;
                self.esr_pending = 0;
            }
            0x300 => return self.send(val, x2),
            0x310 if !x2 => self.icr_hi = v32,
            0x380 => {
                // The initial count means nothing in TSC-deadline mode.
                if self.timer_mode() != TIMER_DEADLINE {
                    self.initial = v32;
                    self.arm_count(now);
                }
            }
            0x3E0 => self.divide = v32 & 0xB,
            0x3F0 if x2 => {
                if val > 0xFF {
                    return Err(Fault);
                }
                self.deliver(&Ipi {
                    vector: val as u8,
                    delivery: Delivery::Fixed,
                    logical: false,
                    level: false,
                    assert: true,
                    dest: self.id,
                    broadcast: false,
                    shorthand: Shorthand::SelfOnly,
                });
            }
            _ => {
                if let Some(i) = lvt_index(off) {
                    self.write_lvt(i, v32, now)?;
                } else if x2 {
                    // Read-only, absent or reserved in x2APIC mode.
                    return Err(Fault);
                }
                // xAPIC: a write to a read-only register is ignored.
            }
        }
        Ok(Effect::None)
    }

    fn write_lvt(&mut self, i: usize, val: u32, now: u64) -> Result<(), Fault> {
        if i == LVT_TIMER {
            // What expired under the old mask is judged by the old mask: a
            // masked expiry is lost, not delivered when the guest unmasks.
            self.tick(now);
        }
        // Delivery status (12) and remote IRR (14) are read-only.
        let mut v = match i {
            LVT_TIMER => {
                if val >> 17 & 3 == 3 {
                    return Err(Fault);
                }
                val & (0xFF | LVT_MASK | 3 << 17)
            }
            LVT_ERROR => val & (0xFF | LVT_MASK),
            // LINT0 / LINT1 also have polarity and trigger mode.
            4 | 5 => val & (0xFF | 7 << 8 | 1 << 13 | 1 << 15 | LVT_MASK),
            _ => val & (0xFF | 7 << 8 | LVT_MASK),
        };
        if self.svr & SVR_ENABLE == 0 {
            v |= LVT_MASK;
        }
        if i == LVT_TIMER && (v ^ self.lvt[i]) >> 17 & 3 != 0 {
            // Changing the mode disarms what the old mode armed.
            self.timer = Timer::Off;
        }
        self.lvt[i] = v;
        Ok(())
    }

    /// An ICR write: decode, validate, and return the message to send.
    fn send(&mut self, val: u64, x2: bool) -> Result<Effect, Fault> {
        let (lo, dest, broadcast_dest) = if x2 {
            self.icr = val;
            (val as u32, (val >> 32) as u32, 0xFFFF_FFFFu32)
        } else {
            self.icr = (self.icr_hi as u64) << 32 | val & 0xFFFF_FFFF;
            (val as u32, self.icr_hi >> 24, 0xFF)
        };
        let vector = lo as u8;
        let Some(delivery) = Delivery::from_bits(lo >> 8 & 7) else { return Ok(Effect::None) };
        let logical = lo >> 11 & 1 != 0;
        let shorthand = match lo >> 18 & 3 {
            0 => Shorthand::None,
            1 => Shorthand::SelfOnly,
            2 => Shorthand::All,
            _ => Shorthand::AllButSelf,
        };
        if matches!(delivery, Delivery::Fixed | Delivery::LowestPriority) && vector < 16 {
            self.error(ESR_SEND_ILLEGAL_VECTOR);
            return Ok(Effect::None);
        }
        Ok(Effect::Ipi(Ipi {
            vector,
            delivery,
            logical,
            level: lo >> 15 & 1 != 0,
            assert: lo >> 14 & 1 != 0,
            dest,
            broadcast: dest == broadcast_dest && (x2 || !logical),
            shorthand,
        }))
    }
}

/// The vLAPIC timer clock of a guest whose TSC runs at `tsc_khz`: an integer
/// number of TSC cycles per tick of the undivided clock, as close to
/// `want_khz` (the bus clock the guest is to see) as the TSC allows, and the
/// rate in kHz that gives. [`Vlapic::new`] takes the first, CPUID leaf
/// `0x4000_0010` of the guest carries the second: the two must agree or the
/// guest calibrates a timer that runs at another speed. Zero in, zero out.
pub fn timer_clock(tsc_khz: u32, want_khz: u32) -> (u64, u32) {
    if tsc_khz == 0 || want_khz == 0 {
        return (1, 0);
    }
    let per_tick = ((tsc_khz as u64 + want_khz as u64 / 2) / want_khz as u64).max(1);
    (per_tick, (tsc_khz as u64 / per_tick) as u32)
}

/// Deliver `ipi` to the vCPUs of a VM (`apics[i]` is vCPU `i`). `src` is the
/// sending vCPU, `None` for the IOAPIC. Lowest-priority delivery picks the
/// accepting vCPU with the lowest processor priority (the lowest index on a
/// tie). The vCPUs delivered to are returned as a bit mask (vCPU `i` is bit
/// `i`) so the caller can kick the ones that run on other harts.
pub fn route(apics: &mut [Vlapic], src: Option<usize>, ipi: &Ipi) -> u64 {
    let n = apics.len().min(64);
    let mut hit = 0u64;
    for (i, a) in apics.iter().enumerate().take(n) {
        let me = Some(i) == src;
        let take = match ipi.shorthand {
            Shorthand::None => a.accepts(ipi),
            Shorthand::SelfOnly => me,
            Shorthand::All => true,
            Shorthand::AllButSelf => !me,
        };
        if take {
            hit |= 1 << i;
        }
    }
    if ipi.delivery == Delivery::LowestPriority && hit != 0 {
        let pick = (0..n).filter(|&i| hit >> i & 1 != 0).min_by_key(|&i| apics[i].ppr()).unwrap_or(0);
        hit = 1 << pick;
    }
    for (i, a) in apics.iter_mut().enumerate().take(n) {
        if hit >> i & 1 != 0 {
            a.deliver(ipi);
        }
    }
    hit
}
