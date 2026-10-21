// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Vm object and the table of them.
//!
//! A [`Vm`] is born *Admitted* from a topology `[guest.NAME]` row
//! ([`VmTable::install`]) and holds nothing: no memory, no tables. Its stage-2
//! root arrives with [`Vm::created`] (the VM interface's `create`); the RAM
//! (MemObjs the VM's monitor made, [`VmTable::check_ram`] / [`VmTable::ram_added`]),
//! the trap page and the NIC ring are attached to it afterwards, and a vCPU
//! may be [`VmTable::start`]ed once RAM and trap page are there. Everything is
//! given back by [`VmTable::destroyed`], which also puts the VM's vCPUs back
//! as admission made them and is refused while one runs. The table is plain
//! data: the kernel keeps it behind its own lock, so the core never decides
//! how it is shared.

use azos_arch_api::{HvKind, Stage2Root, STAGE_PAGE};
use azos_topology::{Envelope, GuestSpec, GUEST_DEVICES, MAX_GUESTS};

use crate::admit::Admitted;
use crate::backend::{self, Backend, Reach};
use crate::ring::{Mailbox, RawPage};
use crate::vcpu::{pick_hart, BadIrq, RunState, Vcpu};

/// Guests the table holds: one per topology row.
pub const MAX_VMS: usize = MAX_GUESTS;
/// vCPUs in the pool, over all VMs (Kconfig `HV_MAX_VCPUS`).
pub const MAX_VCPUS: usize = azos_limits::HV_MAX_VCPUS as usize;
/// Device windows per VM: a memory-mapped and a port window for each backend.
pub const MAX_WINDOWS: usize = 2 * GUEST_DEVICES;

/// The badge of VM `index`'s endpoint (`vm.<index>`), and the subject of the
/// decisions its guest causes.
pub const fn vm_badge(index: u8) -> u32 {
    index as u32 + 1
}

/// Where a guest's RAM starts by default: the address the platform's own
/// machine model puts it at, so a guest kernel built for that machine finds
/// its memory (RISC-V `virt` and ARM `virt` map RAM there; a PC has it at 0).
pub const fn default_ram_base(kind: HvKind) -> u64 {
    match kind {
        HvKind::RiscvH => 0x8000_0000,
        HvKind::ArmEl2 => 0x4000_0000,
        HvKind::X86Svm | HvKind::X86Vmx => 0,
    }
}

/// Where a VM is in its life. Whether its vCPUs run is each [`Vcpu`]'s own
/// [`RunState`]: the VM is *Created* from its tables until it is destroyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VmState {
    /// Declared and admitted at boot; owns nothing.
    Admitted = 0,
    /// Stage-2 tables exist; RAM, the trap page and the vCPUs attach to it.
    Created = 1,
}

/// A transition the state does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadState {
    pub from: VmState,
}

/// Address space of a device window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Space {
    /// Guest-physical addresses.
    Mmio,
    /// x86 I/O ports.
    Pio,
}

/// A range of one address space that a backend serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub space: Space,
    pub base: u64,
    pub len: u64,
    /// Index into the guest's `devices` list.
    pub device: u8,
}

impl Window {
    const fn end(&self) -> u64 {
        self.base + self.len
    }
}

/// Why a window was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    /// Empty, or past the address space.
    BadRange,
    /// The device index is not in the guest's `devices` list.
    NoSuchDevice,
    /// Overlaps another window of the same space.
    Overlap,
    /// A memory window inside the guest's RAM.
    InRam,
    /// The table of windows is full.
    Full,
    /// A vCPU of the VM runs: its loop works on the windows it started with.
    Running,
}

/// A range of guest RAM attached to a VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamSeg {
    pub gpa: u64,
    pub bytes: u64,
}

/// Why a range was refused as RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RamError {
    NoSuchVm,
    /// The VM has no stage-2 tables yet.
    NotCreated,
    /// A vCPU runs.
    Running,
    /// Empty, or not whole 4 KiB pages at a 4 KiB boundary.
    Misaligned,
    /// Not inside the VM's RAM window.
    OutOfRange,
    /// Overlaps RAM attached before.
    Overlap,
}

/// Why a vCPU was not started or stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    NoSuchVcpu,
    /// The VM has no tables.
    NotCreated,
    /// The ISA's entry primitive is not wired: it cannot run a guest.
    NoEntry,
    /// RAM or the trap page is not all attached.
    NotReady,
    /// Already running.
    Running,
    /// Not running (to stop).
    NotRunning,
    /// Every hart the vCPU may use holds a deadline reservation, or is
    /// offline.
    NoHart,
}

/// One virtual machine.
#[derive(Clone, Copy, Debug)]
pub struct Vm {
    /// The `[guest.NAME]` row's position in the topology: the badge of the
    /// VM's endpoint is `index + 1`.
    pub index: u8,
    pub state: VmState,
    /// The stage-2 TLB tag: `index + 1`, so 0 stays the host's.
    pub vmid: u16,
    pub cpus: u8,
    pub mem_mib: u32,
    pub envelope: Envelope,
    devices_len: u8,
    /// Where RAM starts in the guest-physical space.
    pub ram_base: u64,
    /// Bytes of RAM attached so far (`<= ram_bytes`).
    pub ram_attached: u64,
    /// The trap page and the event port are attached: MMIO exits have
    /// somewhere to go.
    pub traps: bool,
    /// The NIC ring is attached (the egress check passed).
    pub nic: bool,
    /// The row's backends by kind, 4 bits each ([`backend::pack`]).
    pub kinds: u64,
    /// The stage-2 tables, while the VM is created.
    pub stage2: Option<Stage2Root>,
    /// The first vCPU of the VM in the pool, and how many.
    pub first_vcpu: u8,
    pub vcpus: u8,
    /// The device windows the owner declared. Recorded for the exit path
    /// (the guest-boot step), which looks an access up in them.
    windows: [Option<Window>; MAX_WINDOWS],
    /// Host ticks the guest's clock lags the host's: the time the VM spent
    /// held, every vCPU of it, since it was created. The guest's time is the
    /// host's less this, on every vCPU (see [`VmTable::freeze`]).
    lost: u64,
    /// While every running vCPU is held: the host tick the hold began at.
    hold_since: Option<u64>,
}

impl Vm {
    fn from_row(index: u8, spec: &GuestSpec<'_>, first_vcpu: u8, kind: HvKind) -> Vm {
        Vm {
            index,
            state: VmState::Admitted,
            vmid: index as u16 + 1,
            cpus: spec.cpus,
            mem_mib: spec.mem_mib,
            envelope: spec.envelope,
            devices_len: spec.devices_len,
            ram_base: default_ram_base(kind),
            ram_attached: 0,
            traps: false,
            nic: false,
            kinds: backend::pack(spec.devices()),
            stage2: None,
            first_vcpu,
            vcpus: spec.cpus,
            windows: [None; MAX_WINDOWS],
            lost: 0,
            hold_since: None,
        }
    }

    /// Backends the guest is given.
    pub fn devices_len(&self) -> usize {
        self.devices_len as usize
    }

    /// Guest RAM in bytes.
    pub fn ram_bytes(&self) -> u64 {
        (self.mem_mib as u64) << 20
    }

    fn move_to(&mut self, ok: bool, to: VmState) -> Result<(), BadState> {
        if ok {
            self.state = to;
            Ok(())
        } else {
            Err(BadState { from: self.state })
        }
    }

    /// RAM and tables now exist.
    pub fn created(&mut self, s2: Stage2Root) -> Result<(), BadState> {
        self.move_to(self.state == VmState::Admitted, VmState::Created)?;
        self.stage2 = Some(s2);
        Ok(())
    }

    /// Everything is given back: the VM is *Admitted* again and may be
    /// recreated. The caller has freed the tables and the RAM.
    fn destroyed(&mut self) -> Result<(), BadState> {
        self.move_to(self.state == VmState::Created, VmState::Admitted)?;
        self.stage2 = None;
        self.windows = [None; MAX_WINDOWS];
        self.ram_attached = 0;
        self.traps = false;
        self.nic = false;
        self.lost = 0;
        self.hold_since = None;
        Ok(())
    }

    /// The backend at device `index` of the row.
    pub fn backend(&self, index: u8) -> Option<Backend> {
        if index as usize >= self.devices_len as usize {
            return None;
        }
        backend::kind_at(self.kinds, index as usize)
    }

    /// The device windows registered so far.
    pub fn windows(&self) -> [Option<Window>; MAX_WINDOWS] {
        self.windows
    }

    /// The window of `space` that holds `addr`.
    pub fn window_at(&self, space: Space, addr: u64) -> Option<Window> {
        self.windows.iter().flatten().copied().find(|w| w.space == space && addr >= w.base && addr < w.end())
    }

    /// Give backend `device` the range `[base, base + len)` of `space`.
    pub fn add_window(&mut self, space: Space, base: u64, len: u64, device: u8) -> Result<(), WindowError> {
        let end = base.checked_add(len).filter(|_| len != 0).ok_or(WindowError::BadRange)?;
        if device as usize >= self.devices_len as usize {
            return Err(WindowError::NoSuchDevice);
        }
        if space == Space::Pio && end > 1 << 16 {
            return Err(WindowError::BadRange);
        }
        if space == Space::Mmio && base < self.ram_base + self.ram_bytes() && end > self.ram_base {
            return Err(WindowError::InRam);
        }
        let w = Window { space, base, len, device };
        if self.windows.iter().flatten().any(|o| o.space == space && base < o.end() && o.base < end) {
            return Err(WindowError::Overlap);
        }
        let slot = self.windows.iter_mut().find(|s| s.is_none()).ok_or(WindowError::Full)?;
        *slot = Some(w);
        Ok(())
    }
}

/// The VMs and the vCPU pool.
pub struct VmTable {
    vms: [Option<Vm>; MAX_VMS],
    vcpus: [Vcpu; MAX_VCPUS],
    vcpus_used: usize,
    /// Answers taken off the completion rings, for the vCPUs that wait.
    mailbox: Mailbox,
}

impl VmTable {
    pub const fn new() -> VmTable {
        VmTable { vms: [None; MAX_VMS], vcpus: [Vcpu::EMPTY; MAX_VCPUS], vcpus_used: 0, mailbox: Mailbox::new() }
    }

    /// Admit the rows `plan` accepted: a [`Vm`] per row, with its vCPUs taken
    /// from the pool. The pool is sized by the plan's own check, so a plan
    /// that came from [`crate::admit::admit`] always fits.
    pub fn install(&mut self, rows: &[GuestSpec<'_>], plan: &Admitted, kind: HvKind) -> Result<(), InstallError> {
        if self.vms.iter().any(|v| v.is_some()) {
            return Err(InstallError::AlreadyInstalled);
        }
        if rows.len() > MAX_VMS || plan.vcpus as usize > MAX_VCPUS {
            return Err(InstallError::NoRoom);
        }
        let mut next = 0usize;
        for (i, row) in rows.iter().enumerate() {
            let vm = Vm::from_row(i as u8, row, next as u8, kind);
            for v in 0..row.cpus as usize {
                let aff = if plan.pinned { nth_set_bit(plan.affinity[i], v as u32) } else { plan.affinity[i] };
                self.vcpus[next + v] = Vcpu::new(i as u8, v as u8, aff);
            }
            next += row.cpus as usize;
            self.vms[i] = Some(vm);
        }
        self.vcpus_used = next;
        Ok(())
    }

    /// VM `index`.
    pub fn vm(&self, index: usize) -> Option<&Vm> {
        self.vms.get(index)?.as_ref()
    }

    pub fn vm_mut(&mut self, index: usize) -> Option<&mut Vm> {
        self.vms.get_mut(index)?.as_mut()
    }

    /// Number of VMs.
    pub fn len(&self) -> usize {
        self.vms.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// vCPU `n` of VM `vm`.
    pub fn vcpu(&self, vm: usize, n: usize) -> Option<&Vcpu> {
        let v = self.vm(vm)?;
        (n < v.vcpus as usize).then(|| &self.vcpus[v.first_vcpu as usize + n])
    }

    pub fn vcpu_mut(&mut self, vm: usize, n: usize) -> Option<&mut Vcpu> {
        let v = self.vm(vm)?;
        let at = (n < v.vcpus as usize).then(|| v.first_vcpu as usize + n)?;
        Some(&mut self.vcpus[at])
    }

    /// Is any vCPU of VM `vm` running?
    pub fn any_running(&self, vm: usize) -> bool {
        self.vm(vm).is_some_and(|v| {
            self.vcpus[v.first_vcpu as usize..v.first_vcpu as usize + v.vcpus as usize]
                .iter()
                .any(|c| c.run_state() == RunState::Running)
        })
    }

    /// Give backend `device` of VM `vm` a window ([`Vm::add_window`]). Refused
    /// while a vCPU runs: the run loop works on the windows it started with.
    pub fn add_window(&mut self, vm: usize, space: Space, base: u64, len: u64, device: u8) -> Result<(), WindowError> {
        if self.any_running(vm) {
            return Err(WindowError::Running);
        }
        self.vm_mut(vm).ok_or(WindowError::NoSuchDevice)?.add_window(space, base, len, device)
    }

    /// May a range of `bytes` at guest-physical `gpa` become RAM of VM `vm`,
    /// given the ranges already attached (`segs`)? The VM is created, no vCPU
    /// runs, the range is whole 4 KiB pages inside the VM's RAM window
    /// (`ram_base`, `mem_mib`) and overlaps none of `segs`. Checks only: the
    /// caller maps the frames, then records them with [`VmTable::ram_added`],
    /// in the one hold of the lock.
    pub fn check_ram(&self, vm: usize, segs: &[RamSeg], gpa: u64, bytes: u64) -> Result<(), RamError> {
        let v = self.vm(vm).ok_or(RamError::NoSuchVm)?;
        if v.state != VmState::Created {
            return Err(RamError::NotCreated);
        }
        if self.any_running(vm) {
            return Err(RamError::Running);
        }
        if bytes == 0 || gpa % STAGE_PAGE != 0 || bytes % STAGE_PAGE != 0 {
            return Err(RamError::Misaligned);
        }
        let end = gpa.checked_add(bytes).ok_or(RamError::OutOfRange)?;
        if gpa < v.ram_base || end > v.ram_base + v.ram_bytes() {
            return Err(RamError::OutOfRange);
        }
        if segs.iter().any(|s| gpa < s.gpa + s.bytes && s.gpa < end) {
            return Err(RamError::Overlap);
        }
        Ok(())
    }

    /// `bytes` more of VM `vm`'s RAM are attached.
    pub fn ram_added(&mut self, vm: usize, bytes: u64) {
        if let Some(v) = self.vm_mut(vm) {
            v.ram_attached += bytes;
        }
    }

    /// The trap page and the event port of VM `vm` are attached. Once.
    pub fn traps_attached(&mut self, vm: usize) -> Result<(), BadState> {
        let running = self.any_running(vm);
        let v = self.vm_mut(vm).ok_or(BadState { from: VmState::Admitted })?;
        if v.state != VmState::Created || v.traps || running {
            return Err(BadState { from: v.state });
        }
        v.traps = true;
        Ok(())
    }

    /// Would a guest of VM `vm` be allowed the effects of `reach`?
    pub fn egress_allowed(&self, vm: usize, reach: Reach) -> bool {
        self.vm(vm).is_some_and(|v| backend::allows(v.envelope, reach))
    }

    /// The NIC ring of VM `vm` is attached. The caller has asked
    /// [`VmTable::egress_allowed`] for [`Reach::Net`] first. Once.
    pub fn nic_attached(&mut self, vm: usize) -> Result<(), BadState> {
        let v = self.vm_mut(vm).ok_or(BadState { from: VmState::Admitted })?;
        if v.state != VmState::Created || v.nic {
            return Err(BadState { from: v.state });
        }
        v.nic = true;
        Ok(())
    }

    /// Start vCPU `k` of VM `vm`: the hart its thread is created on. The VM is
    /// created with all its RAM and the trap page attached, the vCPU not
    /// running, and a hart is left for it that holds no deadline reservation
    /// ([`pick_hart`]); `can_enter` is whether the ISA runs a guest at all.
    /// The vCPU is then *Running*: the caller creates the thread, and if it
    /// cannot, calls [`VmTable::ended`]. `now` is the host's clock: a vCPU
    /// that runs ends a hold the others were in ([`VmTable::freeze`]).
    pub fn start(&mut self, vm: usize, k: usize, can_enter: bool, online: u64, rt: u64, now: u64) -> Result<u8, StartError> {
        let v = *self.vm(vm).ok_or(StartError::NoSuchVcpu)?;
        let c = self.vcpu(vm, k).ok_or(StartError::NoSuchVcpu)?;
        if v.state != VmState::Created {
            return Err(StartError::NotCreated);
        }
        if !can_enter {
            return Err(StartError::NoEntry);
        }
        if v.ram_attached != v.ram_bytes() || !v.traps {
            return Err(StartError::NotReady);
        }
        if c.run_state() == RunState::Running {
            return Err(StartError::Running);
        }
        let hart = pick_hart(c.affinity, online, rt, k as u8).ok_or(StartError::NoHart)?;
        self.vcpu_mut(vm, k).ok_or(StartError::NoSuchVcpu)?.set_running();
        self.settle(vm, now);
        if cfg!(feature = "canary-clock-per-vcpu") {
            // Canary: a vCPU that starts begins a clock of its own.
            self.vm_mut(vm).ok_or(StartError::NoSuchVcpu)?.lost = 0;
        }
        Ok(hart)
    }

    /// vCPU `k` of VM `vm` holds the guest, at host tick `now`.
    ///
    /// **The VM has one clock.** The guest's time is the host's less the time
    /// the VM was held ([`VmTable::lost`]), the same on every vCPU, so a vCPU that
    /// starts later (a guest's `hart_start`, `CPU_ON`, an AP's SIPI, or a
    /// restart after a stop) finds the clock the running ones read. It is held
    /// while *every running* vCPU holds the guest: the interval opens when the
    /// last one freezes and closes at the first change after it (a vCPU
    /// thaws, ends, or starts), so nothing reads the clock inside it and it
    /// never steps back. One vCPU held while another runs does not stop the
    /// clock: the one that runs reads it, and the held one finds it later when
    /// it thaws, as a vCPU the host did not schedule would.
    pub fn freeze(&mut self, vm: usize, k: usize, now: u64) {
        if let Some(c) = self.vcpu_mut(vm, k) {
            c.freeze();
        }
        self.settle(vm, now);
    }

    /// vCPU `k` of VM `vm` leaves the hold, at host tick `now` ([`VmTable::freeze`]).
    pub fn thaw(&mut self, vm: usize, k: usize, now: u64) {
        if let Some(c) = self.vcpu_mut(vm, k) {
            c.thaw();
        }
        self.settle(vm, now);
    }

    /// Host ticks the guest's clock of VM `vm` lags the host's: what the
    /// intervals closed so far took ([`VmTable::freeze`]).
    pub fn lost(&self, vm: usize) -> u64 {
        self.vm(vm).map_or(0, |v| v.lost)
    }

    /// Open or close the VM's hold after a change of which vCPUs run or are
    /// held.
    fn settle(&mut self, vm: usize, now: u64) {
        let Some(v) = self.vm(vm).copied() else { return };
        let (first, n) = (v.first_vcpu as usize, v.vcpus as usize);
        let running = self.vcpus[first..first + n].iter().filter(|c| c.run_state() == RunState::Running);
        let (running, held) = running.fold((0, 0), |(r, h), c| (r + 1, h + c.is_paused() as usize));
        let all_held = running > 0 && held == running;
        let Some(v) = self.vm_mut(vm) else { return };
        match (v.hold_since, all_held) {
            (None, true) => v.hold_since = Some(now),
            (Some(since), false) => {
                // No vCPU left to read the clock is not time the guest lost.
                if running > 0 {
                    // A tick read before the interval opened adds nothing.
                    v.lost = v.lost.wrapping_add(now.saturating_sub(since));
                }
                v.hold_since = None;
            }
            _ => {}
        }
    }

    /// Ask the thread of vCPU `k` to end. It does at its next exit.
    pub fn stop(&mut self, vm: usize, k: usize) -> Result<(), StartError> {
        let c = self.vcpu_mut(vm, k).ok_or(StartError::NoSuchVcpu)?;
        if c.run_state() != RunState::Running {
            return Err(StartError::NotRunning);
        }
        c.request_stop();
        Ok(())
    }

    /// The thread of vCPU `k` ended: `fault` is the exit it could not serve,
    /// `None` for a stop. `now` is the host's clock ([`VmTable::freeze`]).
    pub fn ended(&mut self, vm: usize, k: usize, fault: Option<u64>, now: u64) {
        if let Some(c) = self.vcpu_mut(vm, k) {
            c.set_ended(fault);
        }
        self.settle(vm, now);
        if let Some(at) = self.vm(vm).map(|v| v.first_vcpu as usize + k) {
            self.mailbox.forget(at);
        }
    }

    /// The sequence number of the next trap of vCPU `k` of VM `vm`.
    pub fn next_seq(&mut self, vm: usize, k: usize) -> u32 {
        match self.vm(vm).filter(|v| k < v.vcpus as usize).map(|v| v.first_vcpu as usize) {
            Some(base) => self.mailbox.next_seq(base, k as u8),
            None => 0,
        }
    }

    /// vCPU `k` of VM `vm` has posted trap `seq` and now waits for its answer.
    pub fn expect(&mut self, vm: usize, k: usize, seq: u32) {
        if let Some(at) = self.vm(vm).filter(|v| k < v.vcpus as usize).map(|v| v.first_vcpu as usize + k) {
            self.mailbox.expect(at, seq);
        }
    }

    /// Move the answers on VM `vm`'s completion ring to the vCPUs they answer.
    pub fn collect(&mut self, vm: usize, page: &mut RawPage) {
        if let Some((base, vcpus)) = self.vm(vm).map(|v| (v.first_vcpu as usize, v.vcpus as usize)) {
            self.mailbox.fill(page, base, vcpus);
        }
    }

    /// The answer waiting for vCPU `k` of VM `vm`, if it is here.
    pub fn answer(&mut self, vm: usize, k: usize) -> Option<crate::trapwire::Completion> {
        let at = self.vm(vm).filter(|v| k < v.vcpus as usize).map(|v| v.first_vcpu as usize + k)?;
        self.mailbox.take(at)
    }

    /// The virtual interrupt lines raised for vCPU `k` since it last took
    /// them.
    pub fn take_irqs(&mut self, vm: usize, k: usize) -> u64 {
        self.vcpu_mut(vm, k).map_or(0, |c| c.take_irqs())
    }

    /// The VM's RAM and tables are back: it is *Admitted* again and each of
    /// its vCPUs is as admission made it (no interrupt left pending, the
    /// affinity the topology gave). A VM recreated afterwards starts clean.
    /// Refused while a vCPU runs.
    pub fn destroyed(&mut self, vm: usize) -> Result<(), BadState> {
        if self.any_running(vm) {
            return Err(BadState { from: VmState::Created });
        }
        self.vm_mut(vm).ok_or(BadState { from: VmState::Admitted })?.destroyed()?;
        let v = self.vms[vm].as_ref().map(|v| (v.first_vcpu as usize, v.vcpus as usize));
        if let Some((first, n)) = v {
            for (i, c) in self.vcpus[first..first + n].iter_mut().enumerate() {
                c.reset();
                self.mailbox.reset(first + i);
            }
        }
        Ok(())
    }

    /// Raise virtual interrupt line `irq` of vCPU `k` of VM `vm`. Refused
    /// unless the VM has been created: an admitted VM has no stage-2 tables
    /// and no RAM for the line to be taken in.
    pub fn inject(&mut self, vm: usize, k: usize, irq: u32) -> Result<(), InjectError> {
        match self.vm(vm).map(|v| v.state) {
            None => return Err(InjectError::NoSuchVcpu),
            Some(VmState::Created) => {}
            Some(VmState::Admitted) => return Err(InjectError::NotCreated),
        }
        self.vcpu_mut(vm, k).ok_or(InjectError::NoSuchVcpu)?.inject(irq).map_err(|BadIrq| InjectError::BadIrq)
    }

    /// vCPUs taken from the pool.
    pub fn vcpus_used(&self) -> usize {
        self.vcpus_used
    }
}

/// The mask holding only the `n`-th (from 0) set bit of `mask`; 0 past the last.
fn nth_set_bit(mut mask: u64, n: u32) -> u64 {
    for _ in 0..n {
        mask &= mask.wrapping_sub(1);
    }
    mask & mask.wrapping_neg()
}

/// Why a plan could not be installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// The table already holds VMs (the boot installs once).
    AlreadyInstalled,
    NoRoom,
}

/// Why an interrupt was not raised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InjectError {
    NoSuchVcpu,
    /// The VM is admitted but not created.
    NotCreated,
    /// A line past the 64 a vCPU tracks.
    BadIrq,
}
