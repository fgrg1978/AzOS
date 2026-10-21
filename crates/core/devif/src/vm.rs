// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Vm` and `Vcpu` interfaces: the control plane of a guest.
//!
//! A guest is a `[guest.NAME]` row of the signed topology, admitted at boot
//! (crates/core/hv). Its endpoints are kernel-hosted: `endpoint = "vm.<n>"`
//! names VM `n` (the row's position; badge `n + 1`), `endpoint =
//! "vcpu.<n>.<k>"` its virtual CPU `k` (badge `(n + 1) << 8 | k`). The rights
//! are the usual op classes: `READ` observes, `WRITE` acts on a running guest
//! (an interrupt, a wake-up), `EXEC` controls its life and layout.
//!
//! # What the monitor hands the kernel, and how
//!
//! The VM's ring-3 monitor (`VMMD.ELF`) makes the memory a guest uses and
//! attaches it to the VM; the kernel keeps its own reference on each object
//! until `destroy`. Every capability in a request is *resolved in place* in
//! the caller's table (the entries are not moved, as `Uart::attach`'s are
//! not): it must be a memory object or port the caller made, with the rights
//! the op says.
//!
//! * [`Vm::ram`]: a MemObj becomes guest RAM at a guest-physical address
//!   (stage-2 mapping over its frames). Repeatable: a MemObj holds at most
//!   `MAX_MEMOBJ_PAGES` pages, so a guest is many.
//! * [`Vm::traps`]: the page of the trap and completion rings and the event
//!   port that wakes the monitor when a guest access needs a device model.
//! * [`Vm::net`]: the ring region of the guest's NIC; attaching it is the
//!   guest's egress to the network, so the VM's envelope is asked first.
//!
//! The data plane is not calls: a guest's device accesses reach the monitor
//! on the trap ring (`azos_hv::trapwire`) and nothing a guest does needs a
//! call on these interfaces. The calls are authority (attach, start, stop)
//! and the one wake-up a device model owes a vCPU waiting on its answer
//! ([`Vcpu::kick`]).
//!
//! A vCPU is a kernel thread on a hart that holds no deadline reservation.
//! `start` is `UNSUPPORTED` where the ISA's entry into a guest is not wired
//! (the guest-boot step, S6): there a VM can be built and served, not run.

use crate::outcome::Out;
use azos_idl::{azos_interface, Cap};

/// The `Vm` interface id (ASCII "VM", then 0001).
pub const VM_ID: u32 = 0x564D_0001;
/// The `Vcpu` interface id (ASCII "VM", then 0002).
pub const VCPU_ID: u32 = 0x564D_0002;

/// What a `Cap<GuestRam>` names: a memory object the caller made (read-write,
/// not shared with a clone) that becomes a range of the guest's RAM.
pub struct GuestRam;
/// What a `Cap<TrapPage>` names: one page, [`TRAP_PAGE_BYTES`] of it laid out
/// as `azos_hv::trapwire`, shared between the kernel and the monitor.
pub struct TrapPage;
/// What a `Cap<EventPort>` names: a port (`WRITE`) that gets an event when a
/// trap is posted. The monitor sleeps on it.
pub struct EventPort;
/// What a `Cap<NicRing>` names: the region of the guest NIC's ring pair.
pub struct NicRing;

/// Bytes of the trap page the interface expects (`azos_hv::trapwire::PAGE_BYTES`).
pub const TRAP_PAGE_BYTES: usize = 0x40 + 64 * 32 + 64 * 16;

/// [`Vcpu::state`]: not running (never started, stopped).
pub const RUN_STOPPED: u64 = 0;
/// [`Vcpu::state`]: a thread runs it.
pub const RUN_RUNNING: u64 = 1;
/// [`Vcpu::state`]: the thread ended on an exit nothing serves; bits 8..64 say
/// which (`azos_hv::run::fault_code`).
pub const RUN_FAULTED: u64 = 2;

/// [`Vcpu::state`], when [`RUN_RUNNING`]: bit set while the thread holds the
/// guest ([`Vcpu::pause`] was asked and the thread took the hold). The vCPU
/// still runs in every other sense: it is not stopped, and its state is kept.
pub const RUN_PAUSED: u64 = 1 << 8;

/// [`Vm::window`]'s `space`: guest-physical addresses.
pub const SPACE_MMIO: u32 = 0;
/// [`Vm::window`]'s `space`: x86 I/O ports.
pub const SPACE_PIO: u32 = 1;

/// VMs the interface can name (the topology's table size ceiling).
pub const VMS: u32 = 16;
/// vCPUs per VM the interface can name.
pub const VCPUS: u32 = 256;

/// The badge of `vm.<n>`.
pub const fn vm_badge(n: u32) -> u32 {
    n + 1
}

/// The badge of `vcpu.<n>.<k>`.
pub const fn vcpu_badge(n: u32, k: u32) -> u32 {
    (n + 1) << 8 | k
}

#[azos_interface(id = 0x564D_0001, level = 1)]
pub trait Vm {
    /// The VM's life: 0 admitted, 1 created. Needs `READ`.
    #[idempotent]
    fn state(&self) -> Out<u32>;
    /// What the row declares: `[cpus, mem_mib, envelope | devices << 8 | vmid
    /// << 16, backends, ram_base]` with the envelope as 0 full, 1 cautious, 2
    /// slow, 3 contained; `backends` the kind of each device of the row, 4
    /// bits each from the lowest (1 virtio-blk, 2 virtio-net, 3
    /// virtio-console, 4 virtio-rng, 5 virtio-input, 6 gpio); `ram_base` the
    /// guest-physical address its RAM starts at. Needs `READ`.
    #[idempotent]
    fn config(&self) -> Out<[u64; 5]>;
    /// Build the stage-2 tables. The guest's RAM is [`Vm::ram`]'s. `BUSY`
    /// unless the VM is admitted; `UNSUPPORTED` where the CPU gives no
    /// virtualization extension; `FAULT` when memory ran out (nothing is left
    /// allocated). Needs `EXEC`.
    fn create(&mut self) -> Out<()>;
    /// Give the tables, the RAM and every attachment back. `BUSY` unless the
    /// VM is created, and while a vCPU runs (stop it first). Needs `EXEC`.
    fn destroy(&mut self) -> Out<()>;
    /// Give backend `device` (an index in the row's `devices`) the range
    /// `[base, base + len)` of `space` ([`SPACE_MMIO`] or [`SPACE_PIO`]): the
    /// guest's accesses there are served by its device model. `BAD_ARGUMENT`
    /// for an empty or overlapping range, a memory range inside RAM or a
    /// device the row does not list; `BUSY` while a vCPU runs. Needs `EXEC`.
    fn window(&mut self, space: u32, base: u64, len: u64, device: u32) -> Out<()>;
    /// Attach the memory object `mem` as guest RAM at guest-physical `gpa`
    /// (page-aligned, inside `[ram_base, ram_base + mem_mib MiB)`, overlapping
    /// no RAM attached before). The object must be a read-write memory object
    /// the caller holds with `READ | WRITE`, of the kernel's page size, not
    /// swappable and not shared with a clone; the kernel pins it and keeps its
    /// own reference until `destroy`. `BAD_ARGUMENT` for a handle that is not
    /// such an object or a range outside the window; `BUSY` unless the VM is
    /// created, or while a vCPU runs; `FAULT` when the tables ran out of
    /// memory (nothing of this call stays mapped). Needs `EXEC`.
    fn ram(&mut self, mem: Cap<GuestRam>, gpa: u64) -> Out<()>;
    /// Attach the trap page and the event port `events` (a port with `WRITE`):
    /// a guest access to a window is posted on the page's trap ring and
    /// `events` gets an event carrying `key`. The page is a read-write
    /// memory object of [`TRAP_PAGE_BYTES`] or more, held with `READ |
    /// WRITE`. Once per VM. `BAD_ARGUMENT` for handles of another kind;
    /// `BUSY` unless the VM is created, if already attached, or while a vCPU
    /// runs. Needs `EXEC`.
    fn traps(&mut self, page: Cap<TrapPage>, events: Cap<EventPort>, key: u64) -> Out<()>;
    /// Attach the ring region of the guest's NIC: the guest may then reach
    /// the network through it. Refused with `REFUSED` (recorded as a
    /// guest-egress refusal) when the VM's envelope allows no network. Once
    /// per VM. `BAD_ARGUMENT` for a handle that is not a read-write memory
    /// object held with `READ | WRITE`; `BUSY` unless the VM is created or if
    /// already attached. Needs `EXEC`.
    fn net(&mut self, ring: Cap<NicRing>) -> Out<()>;
}

#[azos_interface(id = 0x564D_0002, level = 1)]
pub trait Vcpu {
    /// The virtual interrupt lines raised and not yet taken, bit `n` for line
    /// `n`. Needs `READ`.
    #[idempotent]
    fn pending(&self) -> Out<u64>;
    /// Raise virtual interrupt line `irq` (0..64, else `BAD_ARGUMENT`).
    /// `BUSY` unless the VM is created (an admitted VM has no tables to raise
    /// it in). Needs `WRITE`.
    fn inject(&mut self, irq: u32) -> Out<()>;
    /// Run only on the harts of `mask` (bit `n` is hart `n`), less the
    /// harts that hold a deadline reservation and the ones that are not
    /// online: answers the mask in effect. `BAD_ARGUMENT` when none is left,
    /// `REFUSED` for a vCPU the topology pinned (a static partition). Takes
    /// effect at the next `start`. Needs `EXEC`.
    fn set_affinity(&mut self, mask: u64) -> Out<u64>;
    /// Start the vCPU at guest-physical `pc`, with `arg` in its first argument
    /// register: a kernel thread on a hart that holds no deadline
    /// reservation. `BUSY` unless the VM is created with all its RAM and the
    /// trap page attached, or if the vCPU already runs; `UNSUPPORTED` where
    /// the ISA cannot enter a guest yet; `REFUSED` when every hart the vCPU
    /// may use holds a deadline reservation; `NO_RESOURCE` when no thread
    /// could be made (nothing is left running). Needs `EXEC`.
    fn start(&mut self, pc: u64, arg: u64) -> Out<()>;
    /// Ask the vCPU to stop: its thread ends at the next exit. `BUSY` when it
    /// does not run. Needs `EXEC`.
    fn stop(&mut self) -> Out<()>;
    /// Wake the vCPU if it waits for a device model's answer on the
    /// completion ring: the one call a model owes after it answered. Needs
    /// `WRITE`.
    fn kick(&mut self) -> Out<()>;
    /// Whether the thread runs: [`RUN_STOPPED`], [`RUN_RUNNING`] or
    /// [`RUN_FAULTED`] in the low 8 bits, for a fault the exit that
    /// ended it in the rest, and for a running vCPU [`RUN_PAUSED`] once the
    /// thread holds the guest. Needs `READ`.
    #[idempotent]
    fn state(&self) -> Out<u64>;
    /// Hold the guest: the thread stops entering it at its next look (a
    /// timer tick at most for a guest that never exits), keeping every
    /// register and the interrupt lines raised meanwhile, and the guest's
    /// clock does not count the time held. [`Vcpu::state`] says when the hold
    /// is taken. `BUSY` when the vCPU does not run or a pause is already
    /// asked. Needs `EXEC`.
    fn pause(&mut self) -> Out<()>;
    /// Let a held (or being held) guest run on. `BUSY` when the vCPU does not
    /// run or no pause is asked. Needs `EXEC`.
    fn resume(&mut self) -> Out<()>;
    /// Raise message-signalled interrupt `id` in the guest's interrupt file
    /// (riscv64, the AIA's IMSIC guest files): the identity becomes pending in
    /// the file the vCPU holds, which it is given if it has none, and the
    /// guest takes it when it enabled it. This is how a monitor that holds a
    /// device's interrupt line gives it to the guest. `UNSUPPORTED` where the
    /// ISA or the machine gives guests no such file; `BAD_ARGUMENT` for an `id`
    /// the monitor cannot raise (the file's identities are `1..=48` here, and
    /// not past what the machine's IMSIC implements); `BUSY` unless the VM is
    /// created. Needs `WRITE`.
    fn inject_msi(&mut self, id: u32) -> Out<()>;
}
