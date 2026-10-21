// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the exit service asks of a guest vCPU's local APIC.
//!
//! The virtual LAPIC and IOAPIC are a pure model in `azos_hv` (`vlapic`,
//! `vioapic`), shared by the vCPUs of a VM; this crate sits below the monitor
//! and does not depend on it. The service here is written against this trait,
//! and the monitor's end implements it for one vCPU over the VM's APICs: an
//! `RDMSR`/`WRMSR` of the APIC base, the TSC-deadline or the x2APIC window
//! goes to [`LocalApic::msr_read`] / [`LocalApic::msr_write`], whatever a
//! write asks of the other vCPUs or the IOAPIC (an IPI, a level EOI) being the
//! implementation's to route, and the entry path drains the interrupt and
//! the non-vector events through the rest.

/// A refused access: the exit service injects `#GP(0)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gp;

/// A non-vector event for the vCPU (`azos_hv::vlapic::Event`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApicEvent {
    /// INIT: reset the vCPU and wait for the startup IPI.
    Init,
    /// Startup IPI with this vector: the vCPU starts at `vector << 12`.
    Startup(u8),
    Smi,
    Nmi,
    ExtInt,
}

/// `IA32_APIC_BASE`.
pub const MSR_APIC_BASE: u32 = 0x1B;
/// `IA32_TSC_DEADLINE`.
pub const MSR_TSC_DEADLINE: u32 = 0x6E0;
/// First MSR of the x2APIC window.
pub const MSR_X2APIC_FIRST: u32 = 0x800;
/// One past the last MSR of the x2APIC window.
pub const MSR_X2APIC_END: u32 = 0x900;

/// Is `msr` one the local APIC serves?
pub const fn is_apic_msr(msr: u32) -> bool {
    msr == MSR_APIC_BASE || msr == MSR_TSC_DEADLINE || (msr >= MSR_X2APIC_FIRST && msr < MSR_X2APIC_END)
}

/// One vCPU's local APIC, as the exit service uses it. `tsc` is always the
/// guest's TSC (host TSC plus the VMCB's offset).
pub trait LocalApic {
    /// A trapped `RDMSR` of an MSR [`is_apic_msr`] names.
    fn msr_read(&mut self, msr: u32, tsc: u64) -> Result<u64, Gp>;
    /// A trapped `WRMSR`; the implementation routes what it asks of other
    /// vCPUs or the IOAPIC.
    fn msr_write(&mut self, msr: u32, val: u64, tsc: u64) -> Result<(), Gp>;
    /// Fire the timer if its time has come.
    fn tick(&mut self, tsc: u64);
    /// The vector to inject next, if one beats the processor priority.
    fn pending(&self) -> Option<u8>;
    /// The vector was injected: requested -> in service.
    fn ack(&mut self) -> Option<u8>;
    /// The next non-vector event.
    fn take_event(&mut self) -> Option<ApicEvent>;
    /// Anything requested at all, deliverable or not: the vCPU must not sleep.
    fn has_work(&self) -> bool;
    /// The guest TSC at which the timer next needs [`LocalApic::tick`].
    fn next_deadline(&self) -> Option<u64>;
    /// The register state an INIT leaves.
    fn init_reset(&mut self);
    /// Is `gpa` a register of the VM's interrupt controllers: this vCPU's
    /// xAPIC page (while the guest has it in xAPIC mode) or the IOAPIC window?
    /// The nested page tables map neither, so a guest access exits, and the
    /// service answers it here instead of posting it to a device model.
    fn owns_mmio(&self, gpa: u64) -> bool;
    /// A 32-bit load from such a register (an access the model refuses reads 0).
    fn mmio_read(&mut self, gpa: u64, size: u8, tsc: u64) -> u32;
    /// A store to such a register (an access the model refuses is dropped);
    /// what it asks of other vCPUs is the implementation's to route.
    fn mmio_write(&mut self, gpa: u64, size: u8, val: u32, tsc: u64);
}
