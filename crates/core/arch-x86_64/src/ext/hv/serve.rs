// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The exits of an x86 guest that need no device model: [`VcpuState::serve`]
//! answers them from the VMCB, the general registers and the vCPU's local
//! APIC, and [`VcpuState::before_entry`] prepares the next `VMRUN`.
//!
//! # What an exit becomes
//!
//! | exit | served as |
//! |------|-----------|
//! | `CPUID` | [`super::cpuid::answer`] |
//! | `RDMSR` / `WRMSR` | [`super::msr`]; a refusal is `#GP(0)` |
//! | `XSETBV` | the guest's `XCR0`, kept here (it is not in the VMCB) and validated against what CPUID offers |
//! | `HLT` | [`Served::Wait`] unless the APIC has something for the vCPU |
//! | `VINTR` | the interrupt window opened: withdrawn, and the entry path injects |
//! | `IRET` (only while an NMI is being handled) | the end of NMI blocking is noted, see "NMI" below |
//! | `WBINVD`, `INVD` | skipped: the guest cannot flush the host's caches |
//! | `RDTSCP`, `MONITOR`, `MWAIT`, `SKINIT`, `VMRUN`, `VMLOAD`, `VMSAVE`, `STGI`, `CLGI` | `#UD`: CPUID does not offer them |
//! | a nested page fault on an address no RAM backs | the instruction is decoded ([`super::mmio`]): the interrupt controllers' registers (xAPIC page, IOAPIC window) are answered here, any other device's is [`Served::Mmio`] for its device model |
//! | a physical interrupt or NMI | [`Served::HostInterrupt`] |
//! | triple fault, a failed entry | [`Served::Shutdown`], [`Served::InvalidState`] |
//! | everything else (port I/O, `VMMCALL`, SMI / INIT, a fault on mapped memory, an instruction the decoder does not know) | [`Served::Unserved`], for the monitor's loop |
//!
//! # Time and interrupts
//!
//! The guest's TSC is the host's plus the VMCB's `TSC_OFFSET`; the vLAPIC
//! timer is in it. The monitor arms one host timer for the vLAPIC's next
//! deadline ([`LocalApic::next_deadline`]); [`VcpuState::before_entry`] fires
//! the timer if due and injects what the APIC has pending, or opens the
//! interrupt window when the guest cannot take it yet. A guest that never
//! exits still takes its timer within a host tick (the physical interrupt
//! that ends the entry), which is the latency of a virtual timer here.
//!
//! # NMI
//!
//! An NMI blocks further NMIs until the handler's `IRET`, and is not taken in
//! the shadow of `sti` / `mov ss`. The VMCB has no bit for the first, so it is
//! kept here: injecting an NMI blocks, and arms the `IRET` intercept; the
//! guest's first `IRET` after that stops *before* it runs, the intercept is
//! withdrawn, and the block ends when the guest's `RIP` has moved off that
//! `IRET` (the next [`VcpuState::before_entry`]). One NMI is latched while
//! blocked, as on hardware, so a guest that sends itself NMIs from the NMI
//! handler gets them one at a time, never nested. An NMI held back by the
//! shadow asks for the interrupt window, which ends the entry as soon as the
//! shadow is over (with interrupts off it waits for the next host tick).
//!
//! # Reading the faulting instruction
//!
//! A nested page fault exits with the guest's other vCPUs still running, so
//! the instruction at `RIP` can be rewritten between the fault and the
//! decode. The bytes are therefore the CPU's own copy (decode assist, in the
//! VMCB); the guest's memory is read only in a VM of one vCPU, where nothing
//! else writes it. In a larger VM a fault the CPU gave no bytes for is
//! [`Served::Unserved`] (the vCPU stops, visibly).
//!
//! # Simplifications
//!
//! * The guest's `XCR0` is the monitor's to load around `VMRUN`
//!   ([`VcpuState::xcr0`]); this file only keeps it.

use azos_arch_api::MmioAccess;

use super::apic::{ApicEvent, Gp, LocalApic};
use super::cpuid::{self, Guest, Leaf};
use super::entry::{Power, Start};
use super::exit::{Exit, NestedFault};
use super::inject::vector;
use super::mmio::{self, GuestMem, Insn, Mode};
use super::msr;
use super::svm::{code, off, GuestRegs, Vmcb};

/// `CR4.OSXSAVE`.
const CR4_OSXSAVE: u64 = 1 << 18;

/// What the next step of the vCPU's thread is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Served {
    /// Served: enter the guest again.
    Resume,
    /// `HLT` with nothing for the vCPU: sleep until a virtual interrupt is
    /// raised or the vCPU is stopped (`Exit::Wait`).
    Wait,
    /// A physical interrupt or NMI ended the entry: the host takes it, then
    /// enters again (`Exit::HostInterrupt`).
    HostInterrupt,
    /// Triple fault (`Exit::Shutdown`).
    Shutdown,
    /// The VMCB failed the entry checks (`Exit::InvalidState`).
    InvalidState,
    /// A load or store to memory-mapped I/O that is not the interrupt
    /// controllers': the device model's. The monitor answers it with
    /// [`VcpuState::finish_mmio`] (a load's value, 0 for a store) before the
    /// next entry. `value` is what a store writes.
    Mmio { access: MmioAccess, value: u64 },
    /// Not an exit this service answers; the loop decides.
    Unserved(Exit),
}

/// What [`VcpuState::before_entry`] decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Entry {
    /// `VMRUN` the guest.
    Run,
    /// The vCPU has not been started (an AP before its SIPI): do not enter;
    /// sleep as for [`Served::Wait`].
    WaitSipi,
}

/// The monitor's end of one guest vCPU's environment.
pub struct Env<'a> {
    /// The host's `CPUID`.
    pub host_cpuid: &'a dyn Fn(u32, u32) -> Leaf,
    /// This vCPU's local APIC.
    pub apic: &'a mut dyn LocalApic,
    /// The guest's memory: the instruction bytes and page tables of a
    /// nested page fault are read through it.
    pub mem: &'a dyn GuestMem,
    /// The host's TSC now.
    pub host_tsc: u64,
}

/// What the service keeps per vCPU besides the VMCB and the registers.
#[derive(Clone, Copy, Debug)]
pub struct VcpuState {
    /// The vCPU's index: its APIC ID.
    pub id: u32,
    /// vCPUs in the VM.
    pub vcpus: u32,
    /// Guest TSC rate in kHz (CPUID leaf `0x4000_0010`); 0 unknown.
    pub tsc_khz: u32,
    /// vLAPIC timer clock in kHz (leaf `0x4000_0010`); 0 unknown.
    pub apic_khz: u32,
    /// The ASID the VMCB runs under.
    pub asid: u32,
    /// The CPU reports the address of the next instruction on an intercept
    /// (`SvmCaps::nrips`); otherwise the lengths below are used.
    pub nrips: bool,
    /// `CPUID.1:EAX` of the guest: the signature an INIT-started AP finds in `EDX`.
    pub signature: u32,
    xcr0: u64,
    power: Power,
    /// An NMI is latched, waiting to be injected.
    nmi: bool,
    /// An NMI was injected and its handler has not returned: no other is.
    nmi_blocked: bool,
    /// The `RIP` of the `IRET` that ended the handler, once it exited; the
    /// block ends when the guest has left it.
    iret_at: Option<u64>,
    /// The access [`Served::Mmio`] handed out, until [`VcpuState::finish_mmio`].
    mmio: Option<Insn>,
}

impl VcpuState {
    /// A vCPU: the boot CPU runs from its first entry, any other waits for
    /// its startup IPI.
    pub fn new(id: u32, vcpus: u32, asid: u32) -> VcpuState {
        VcpuState {
            id,
            vcpus,
            tsc_khz: 0,
            apic_khz: 0,
            asid,
            nrips: false,
            signature: 0,
            xcr0: 1,
            power: if id == 0 { Power::Running } else { Power::WaitSipi },
            nmi: false,
            nmi_blocked: false,
            iret_at: None,
            mmio: None,
        }
    }

    /// The guest's `XCR0`: the monitor loads it before `VMRUN` and puts the
    /// host's back after.
    pub fn xcr0(&self) -> u64 {
        self.xcr0
    }

    pub fn power(&self) -> Power {
        self.power
    }

    fn guest(&self, vmcb: &Vmcb) -> Guest {
        Guest {
            vcpu: self.id,
            vcpus: self.vcpus,
            tsc_khz: self.tsc_khz,
            apic_khz: self.apic_khz,
            xcr0: self.xcr0,
            osxsave: vmcb.rd64(off::CR4) & CR4_OSXSAVE != 0,
        }
    }

    /// Step the guest past the instruction that exited: to the address the
    /// CPU saved, or by the instruction's `len` bytes when it saves none.
    fn skip(&self, vmcb: &mut Vmcb, len: u64) {
        let rip = if self.nrips { vmcb.rd64(off::NEXT_RIP) } else { vmcb.rd64(off::RIP).wrapping_add(len) };
        vmcb.wr64(off::RIP, rip);
    }

    /// Answer the exit `e` of a guest whose state is `vmcb` and `regs`.
    pub fn serve(&mut self, e: Exit, vmcb: &mut Vmcb, regs: &mut GuestRegs, env: &mut Env<'_>) -> Served {
        // An exit in the middle of delivering an event must not lose the event.
        vmcb.requeue_exit_event();
        match e {
            Exit::Cpuid => {
                let (leaf, sub) = (vmcb.rd64(off::RAX) as u32, regs.rcx as u32);
                let l = cpuid::answer(env.host_cpuid, &self.guest(vmcb), leaf, sub);
                vmcb.wr64(off::RAX, l.eax as u64);
                regs.rbx = l.ebx as u64;
                regs.rcx = l.ecx as u64;
                regs.rdx = l.edx as u64;
                self.skip(vmcb, 2);
                Served::Resume
            }
            Exit::Msr { write } => {
                let m = regs.rcx as u32;
                let done = if write {
                    let val = (regs.rdx & 0xFFFF_FFFF) << 32 | (vmcb.rd64(off::RAX) & 0xFFFF_FFFF);
                    msr::write(vmcb, env.apic, m, val, env.host_tsc)
                } else {
                    msr::read(vmcb, env.apic, m, env.host_tsc).map(|v| {
                        vmcb.wr64(off::RAX, v & 0xFFFF_FFFF);
                        regs.rdx = v >> 32;
                    })
                };
                match done {
                    Ok(()) => self.skip(vmcb, 2),
                    Err(Gp) => vmcb.inject_exception(vector::GP, Some(0)),
                }
                Served::Resume
            }
            Exit::Xsetbv => {
                self.xsetbv(vmcb, regs, env);
                Served::Resume
            }
            Exit::Halt => {
                self.skip(vmcb, 1);
                if (self.nmi && !self.nmi_blocked) || env.apic.has_work() { Served::Resume } else { Served::Wait }
            }
            Exit::IntWindow => {
                vmcb.clear_window();
                Served::Resume
            }
            Exit::Interrupt | Exit::Nmi => Served::HostInterrupt,
            Exit::Shutdown => Served::Shutdown,
            Exit::InvalidState => Served::InvalidState,
            Exit::Other(c) => match c {
                code::IRET => {
                    // The handler returns: let it, and end the block once it
                    // has left this instruction.
                    vmcb.set_iret_intercept(false);
                    self.iret_at = Some(vmcb.rd64(off::RIP));
                    Served::Resume
                }
                code::WBINVD | code::INVD => {
                    self.skip(vmcb, 2);
                    Served::Resume
                }
                code::RDTSCP | code::MONITOR | code::MWAIT | code::SKINIT | code::VMRUN | code::VMLOAD
                | code::VMSAVE | code::STGI | code::CLGI => {
                    vmcb.inject_exception(vector::UD, None);
                    Served::Resume
                }
                _ => Served::Unserved(e),
            },
            Exit::NestedFault(f) => self.mmio_fault(e, f, vmcb, regs, env),
            Exit::Io(_) | Exit::Hypercall => Served::Unserved(e),
        }
    }

    /// A nested page fault on a guest-physical address no RAM backs: the
    /// guest loaded from or stored to a device register. Decode the
    /// instruction ([`super::mmio`]); the interrupt controllers' registers are
    /// answered here, the rest go to the device model.
    fn mmio_fault(&mut self, e: Exit, f: NestedFault, vmcb: &mut Vmcb, regs: &mut GuestRegs, env: &mut Env<'_>) -> Served {
        // A permission fault (the page is mapped) and an instruction fetch
        // are not device accesses; so is a fault on the guest's own page
        // tables rather than on the final address.
        if f.present || f.exec || !f.final_translation {
            return Served::Unserved(e);
        }
        let Some(mode) = Mode::of(vmcb) else { return Served::Unserved(e) };
        let Some((code, n)) = mmio::fetch(vmcb, env.mem, mode, self.vcpus == 1) else { return Served::Unserved(e) };
        let Some(insn) = mmio::decode(&code[..n], mode) else { return Served::Unserved(e) };
        if insn.write != f.write {
            // The page-fault error code and the instruction disagree: the
            // bytes are not the instruction that faulted.
            return Served::Unserved(e);
        }
        let tsc = env.host_tsc.wrapping_add(vmcb.rd64(off::TSC_OFFSET));
        if env.apic.owns_mmio(f.gpa) {
            if insn.write {
                env.apic.mmio_write(f.gpa, insn.size, mmio::store_value(&insn, vmcb, regs) as u32, tsc);
                mmio::skip(&insn, vmcb);
            } else {
                let v = env.apic.mmio_read(f.gpa, insn.size, tsc);
                mmio::complete_load(&insn, vmcb, regs, v as u64);
            }
            return Served::Resume;
        }
        self.mmio = Some(insn);
        let value = if insn.write { mmio::store_value(&insn, vmcb, regs) } else { 0 };
        Served::Mmio {
            access: MmioAccess { gpa: f.gpa, size: insn.size, write: insn.write, reg: insn.reg, insn_len: insn.len },
            value,
        }
    }

    /// The device model answered the access [`Served::Mmio`] handed out:
    /// write a load's `value` to its register, and step past the instruction.
    /// `false` when no access was waiting.
    pub fn finish_mmio(&mut self, vmcb: &mut Vmcb, regs: &mut GuestRegs, value: u64) -> bool {
        let Some(insn) = self.mmio.take() else { return false };
        if insn.write {
            mmio::skip(&insn, vmcb);
        } else {
            mmio::complete_load(&insn, vmcb, regs, value);
        }
        true
    }

    fn xsetbv(&mut self, vmcb: &mut Vmcb, regs: &GuestRegs, env: &Env<'_>) {
        // `XSETBV` outside ring 0 is #GP; with `CR4.OSXSAVE` clear it is #UD.
        if vmcb.rd64(off::CR4) & CR4_OSXSAVE == 0 {
            return vmcb.inject_exception(vector::UD, None);
        }
        let val = (regs.rdx & 0xFFFF_FFFF) << 32 | (vmcb.rd64(off::RAX) & 0xFFFF_FFFF);
        if vmcb.rd8(off::CPL) & 3 != 0 || regs.rcx as u32 != 0 || !cpuid::xcr0_valid(env.host_cpuid, val) {
            return vmcb.inject_exception(vector::GP, Some(0));
        }
        self.xcr0 = val;
        self.skip(vmcb, 3);
    }

    /// Prepare the next `VMRUN`: fire the APIC timer if it is due, take the
    /// start events (INIT and startup IPI reset or start the vCPU, NMI is
    /// queued), and inject the vector the APIC has pending, or open the
    /// interrupt window when the guest cannot take it yet.
    pub fn before_entry(&mut self, vmcb: &mut Vmcb, regs: &mut GuestRegs, env: &mut Env<'_>) -> Entry {
        let guest_tsc = env.host_tsc.wrapping_add(vmcb.rd64(off::TSC_OFFSET));
        env.apic.tick(guest_tsc);
        while let Some(ev) = env.apic.take_event() {
            match ev {
                ApicEvent::Init => {
                    let s = self.power.init();
                    self.start(s, vmcb, regs, env);
                }
                ApicEvent::Startup(v) => {
                    let s = self.power.sipi(v);
                    self.start(s, vmcb, regs, env);
                }
                ApicEvent::Nmi => self.nmi = true,
                // SMI is not offered; ExtINT needs an 8259, which the guest
                // does not have.
                ApicEvent::Smi | ApicEvent::ExtInt => {}
            }
        }
        if self.power == Power::WaitSipi {
            return Entry::WaitSipi;
        }
        if self.iret_at.is_some_and(|at| vmcb.rd64(off::RIP) != at) {
            self.nmi_blocked = false;
            self.iret_at = None;
        }
        let mut window = false;
        if self.nmi && !self.nmi_blocked && !vmcb.event_queued() {
            if vmcb.in_shadow() {
                window = true;
            } else {
                self.nmi = false;
                self.nmi_blocked = true;
                self.iret_at = None;
                vmcb.set_iret_intercept(true);
                vmcb.inject_nmi();
            }
        }
        // The vector to inject is the highest requested one, so nothing left
        // requested can beat it: one event per entry loses nothing.
        if let Some(v) = env.apic.pending() {
            if vmcb.can_take_interrupt() {
                vmcb.inject_interrupt(v);
                env.apic.ack();
            } else {
                window = true;
            }
        }
        if window {
            vmcb.request_window();
        } else {
            vmcb.clear_window();
        }
        Entry::Run
    }

    fn start(&mut self, s: Start, vmcb: &mut Vmcb, regs: &mut GuestRegs, env: &mut Env<'_>) {
        match s {
            Start::Nothing => {}
            Start::Reset => {
                env.apic.init_reset();
                self.xcr0 = 1;
                self.nmi = false;
                self.nmi_blocked = false;
                self.iret_at = None;
                // Back to the reset state; the vCPU does not run until its SIPI.
                vmcb.init_startup(regs, 0, self.asid, self.signature);
            }
            Start::Run(v) => vmcb.init_startup(regs, v, self.asid, self.signature),
        }
        // A started or reset vCPU is not inside an NMI handler.
        if s != Start::Nothing {
            vmcb.set_iret_intercept(false);
        }
    }
}
