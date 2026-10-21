// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Vm` and `Vcpu` interfaces the kernel hosts (`endpoint = "vm.<n>"`,
//! `"vcpu.<n>.<k>"`; Kconfig `VIRT`, hypervisor plan step H1).
//!
//! The monitor's state is one [`Monitor`] behind one lock: the table of VMs
//! and vCPUs (`azos_hv::VmTable`), the ISA's [`Hypervisor`] and what each VM
//! was given. The boot installs it once ([`install`], from
//! `kernel/src/boot/hv.rs`) after `azos_hv::admit::admit` accepted the
//! topology's guest rows; until then, and when the image has no hypervisor,
//! every op answers `NOT_READY` / `UNSUPPORTED` and touches nothing.
//!
//! **What `create` builds.** The stage-2 tables, from kernel frames, and
//! nothing else. The guest's memory is the VM's ring-3 monitor's to make and
//! attach.
//!
//! **What the monitor attaches.** Every capability in a request is resolved in
//! place in the caller's table ([`resolve`]); the kernel then takes a
//! reference of its own on the object, **pinned** (`memobj_pin_ref`), so that
//! the frames the guest runs on cannot be resized, revoked or freed under the
//! stage-2 tables whatever the monitor does with its handle. The references
//! go back at `destroy`:
//!
//! * `ram`: a memory object becomes a range of guest RAM
//!   (`azos_hv::stage2::map_frames` over its frames, one at a time, so the
//!   object need not be contiguous). A failure gives back what the call took.
//! * `traps`: the page of the trap and completion rings and the event port.
//! * `net`: the guest NIC's ring region, after the VM's envelope allowed a
//!   network.
//!
//! One object plays one role of one VM ([`attached_anywhere`]).
//!
//! **What `start` runs.** A vCPU is a kernel thread ([`vcpu_main`]) pinned to
//! a hart that holds no deadline reservation, running `azos_hv::run::run`:
//! enter the guest, route the exit, post a device access on the trap ring and
//! signal the event port, wait for the model's answer. The kernel end of that
//! loop is [`KHost`]. The thread ends on `stop`, on an exit nothing serves, or
//! when the monitor's event port is gone. `pause` does not end it: the thread
//! holds the guest where the last exit left it until `resume` (or `stop`), and
//! the guest's clock does not count the time the VM was held ([`guest_now`]):
//! the time every running vCPU held the guest together (`VmTable::freeze`), so
//! pausing one vCPU of an SMP guest leaves its clock running for the others.
//!
//! **What a guest's hypercalls reach.** [`KHost`] is also the VM the ISA's
//! firmware interface works on (`HypercallHost`; the SBI on riscv64): the
//! other vCPUs (start, status, the interrupt lines), the guest's timer and the
//! fences it asks of other vCPUs. The timer and the fence requests live on the
//! [`Vcpu`](azos_hv::vcpu::Vcpu) record, under the monitor's lock like the
//! pending lines. The timer is a level the vCPU's own thread derives on every
//! entry (`take_irqs`), so a vCPU that waits wakes for its deadline; guest time
//! is the host's less the time the VM was held ([`guest_now`]), one clock for
//! all its vCPUs: a vCPU the guest starts later reads what the running ones
//! do. A fence is carried out by the target's thread before its next entry (or
//! while it is held), and the asking vCPU is held until it is (the target runs
//! within a host tick at worst). A guest that ends the machine ends all its vCPUs.
//!
//! Locking: the monitor's lock, then the memory-object table's, never the
//! other way. The thread holds the monitor's lock only to read or write the
//! tables and the ring page, never across a guest entry, a block or a wake-up.

use alloc::vec::Vec;

use azos_abi::cap::{CapHandle, CapPerms};
use azos_arch_api::{
    GuestCtx, HvKind, HvStatus, HypercallHost, Hypervisor, MmioAccess, RemoteFence, StagePerms, StageTableMem,
    VcpuStartError, STAGE_PAGE,
};
use azos_devif::{outcome, Cap as WireCap, Out};
use azos_hv::admit::Admitted;
use azos_hv::backend::{Backend, Reach};
use azos_hv::ring::{Full, RawPage};
use azos_hv::run::{self, PostError, RunHost, RunView, Stop};
use azos_hv::stage2::{map_frames, unmap_range, FrameSource};
use azos_hv::trapwire::{Completion, Trap, PAGE_BYTES};
use azos_hv::vcpu::{PauseError, RunState, TIMER_NEVER};
use azos_hv::vplic::{Vplic, EXTERNAL_LINE, PLIC_DEFAULT_BASE};
use azos_hv::vm::{
    InjectError, RamError, RamSeg, Space, StartError, VmState, VmTable, WindowError, MAX_VCPUS, MAX_VMS,
};
use azos_ipc::cap::{targets, Cap, CapError, CapTarget};
use azos_ipc::memobj::{
    memobj_acquire_ref, memobj_describe_ref, memobj_page_phys_ref, memobj_pin_ref, memobj_release_ref,
    memobj_with_span_ref, MemKind, MemPerms, ATTR_NO_KERNEL_MAP, ATTR_SWAPPABLE, ATTR_VOLATILE, MEMOBJ_KERNEL_OWNER,
};
use azos_ipc::port::{port_live_epoch, port_queue_event_bound, PortEvent, PORT_EVENT_RING};
use azos_mm::addr::{phys_to_virt, PhysAddr};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use azos_sync::SpinLock;
use azos_topology::GuestSpec;

use crate::invoke::class_op;
use crate::khost::Caller;
use azos_abi::invoke::CLASS_CTL;

// The interface and the wire form name the same page.
const _: () = assert!(azos_devif::vm::TRAP_PAGE_BYTES == PAGE_BYTES);

/// How long a vCPU thread waits for a device model's answer, or for an
/// interrupt while its guest waits for one, before it looks again. A `kick`
/// or an `inject` ends the wait early; this is what bounds the cost of a
/// wake-up that came before the thread blocked.
const WAIT_SLICE_NS: u64 = 500_000;

/// Stage-2 table memory from the page allocator, read and written through the
/// direct map. A table is 4 KiB; a kernel frame is one translation granule
/// (`PAGE_SIZE`), so a table costs a whole frame on a 16/64 KiB build.
struct Tables;

impl Tables {
    const fn frames(pages: usize) -> usize {
        (pages * STAGE_PAGE as usize).div_ceil(azos_arch::PAGE_SIZE)
    }
}

impl StageTableMem for Tables {
    fn alloc(&mut self, pages: usize) -> Option<u64> {
        let bytes = pages * STAGE_PAGE as usize;
        let pa = azos_mm::pmm::alloc_contiguous_aligned(Self::frames(pages), bytes.max(azos_arch::PAGE_SIZE)).ok()?;
        Some(pa.as_usize() as u64)
    }

    fn free(&mut self, pa: u64, pages: usize) {
        for i in 0..Self::frames(pages) {
            let _ = azos_mm::pmm::free_page(PhysAddr::new(pa as usize + i * azos_arch::PAGE_SIZE));
        }
    }

    fn read(&self, pa: u64) -> u64 {
        // SAFETY: `pa` is inside a table frame this module allocated and
        // nothing else maps: RAM in the kernel's direct map, 8-byte aligned.
        unsafe { core::ptr::read_volatile(phys_to_virt(pa as usize) as *const u64) }
    }

    fn write(&mut self, pa: u64, word: u64) {
        // SAFETY: as `read`; the monitor's lock is held, so no other writer.
        unsafe { core::ptr::write_volatile(phys_to_virt(pa as usize) as *mut u64, word) }
    }
}

/// The frames of one memory object, a page of the object at a time.
struct ObjFrames {
    obj: u32,
    frames: usize,
}

impl FrameSource for ObjFrames {
    fn frames(&self) -> usize {
        self.frames
    }
    fn frame(&self, idx: usize) -> Option<u64> {
        memobj_page_phys_ref(self.obj, idx).ok().flatten().map(|p| p as u64)
    }
    fn frame_bytes(&self) -> u64 {
        azos_arch::PAGE_SIZE as u64
    }
}

/// What a VM was given, to give back at `destroy`.
#[derive(Default)]
struct Held {
    /// The RAM: the objects (the kernel's pinned reference on each) and
    /// their ranges, in the order attached.
    ram_objs: Vec<u32>,
    ram_segs: Vec<RamSeg>,
    /// The trap page, and the event port the monitor sleeps on.
    traps: Option<Link>,
    /// The NIC ring region.
    nic: Option<u32>,
    /// The guest's interrupt controller, where its ISA has one the monitor
    /// emulates (riscv64: the PLIC); made with the VM's tables.
    plic: Option<Vplic>,
}

/// The trap page and the event port of a VM.
#[derive(Clone, Copy)]
struct Link {
    /// The memory object of the page (the kernel's pinned reference).
    page: u32,
    /// The port, by packed reference and the epoch of its slot.
    port: u32,
    epoch: u32,
    /// The key the event carries.
    key: u64,
}

/// What a vCPU's thread works from, built when it starts.
struct Setup {
    ctx: GuestCtx,
    view: RunView,
    hv: &'static dyn Hypervisor,
    link: Link,
}

/// The monitor.
pub struct Monitor {
    hv: &'static dyn Hypervisor,
    table: VmTable,
    held: [Held; MAX_VMS],
    /// Per vCPU of the pool: the `(pc, arg)` it was started with until its
    /// thread picks them up, and the thread's TID once it runs (for the
    /// wake-ups: [`TIDS`]). The rest of a thread's setup is rebuilt from the
    /// tables, so the monitor, built on the boot stack, stays small.
    pending: [Option<(u64, u64)>; MAX_VCPUS],
    online: u64,
    rt: u64,
    pinned: bool,
}

static MONITOR: SpinLock<Option<Monitor>> = SpinLock::new(None);

/// Per vCPU of the pool, the TID of its thread (0: none), outside the
/// monitor's lock: an interrupt handler wakes a waiting vCPU from here
/// ([`wake_file_owner`]), and the lock is one a thread holds with the
/// interrupts on.
static TIDS: [AtomicU32; MAX_VCPUS] = [const { AtomicU32::new(0) }; MAX_VCPUS];

/// Per vCPU of the pool, who its thread's vCPU is as the hart's guest-file
/// pool names its holders ([`Hypervisor::guest_holder_key`]; 0: none, and on
/// an ISA without guest files always). Set after [`TIDS`], cleared before it.
static HOLDERS: [AtomicU64; MAX_VCPUS] = [const { AtomicU64::new(0) }; MAX_VCPUS];

/// Install the monitor: the boot's, once, after admission accepted `rows`.
/// `online` and `rt` are the hart masks admission used (`rt`: the harts that
/// hold a deadline reservation).
pub fn install(
    hv: &'static dyn Hypervisor,
    rows: &[GuestSpec<'_>],
    plan: &Admitted,
    online: u64,
    rt: u64,
) -> Result<(), azos_hv::vm::InstallError> {
    let mut table = VmTable::new();
    table.install(rows, plan, hv.kind())?;
    let mut m = MONITOR.lock();
    if m.is_some() {
        return Err(azos_hv::vm::InstallError::AlreadyInstalled);
    }
    *m = Some(Monitor {
        hv,
        table,
        held: core::array::from_fn(|_| Held::default()),
        pending: [None; MAX_VCPUS],
        online,
        rt,
        pinned: plan.pinned,
    });
    Ok(())
}

/// vCPUs of VM `vmid` (the 1-based id `GuestCtx::vmid` carries); `None` when
/// no monitor is installed or the VM does not exist. The x86_64 entry builds the
/// VM's virtual APICs from it (`kernel/src/entry/x86_64/ext/hv.rs`).
pub fn vcpus_of(vmid: u16) -> Option<u8> {
    with(|m| m.table.vm((vmid as usize).checked_sub(1)?).map(|v| v.vcpus)).flatten()
}

/// Run `f` on the monitor; `None` when none is installed.
fn with<R>(f: impl FnOnce(&mut Monitor) -> R) -> Option<R> {
    MONITOR.lock().as_mut().map(f)
}

const fn vm_of(badge: u32) -> Option<usize> {
    if badge >= 1 && (badge as usize) <= MAX_VMS { Some(badge as usize - 1) } else { None }
}

/// The caller's capability `raw` as a `T` with `need`, resolved in place (the
/// entry stays in the caller's table): the object it names. A refusal for a
/// right the handle lacks is recorded as a typed denial; anything that is not
/// such a handle is `BAD_ARGUMENT`. Attaching an object steers its life (the VM
/// pins it), so the use is the `CTL` class.
fn resolve<T: CapTarget>(who: &Caller, raw: u32, need: CapPerms) -> Result<u32, u32> {
    let cap: Cap<T> = Cap::from_raw(CapHandle::from_raw(raw));
    match azos_ipc::cap_store::with_table(who.tid, |t| t.get_op(cap, need, class_op(T::TYPE, CLASS_CTL))) {
        Some(Ok(r)) => Ok(r),
        Some(Err(e)) => {
            crate::handlers::note_typed_denial_for(who.tid, T::TYPE, e);
            Err(match e {
                CapError::MissingPerms | CapError::Contained => outcome::DENIED,
                _ => outcome::BAD_ARGUMENT,
            })
        }
        None => Err(outcome::BAD_ARGUMENT),
    }
}

/// Take the kernel's pinned reference on the memory object `obj`: from then on
/// it cannot be resized, revoked or freed while the kernel holds the frames.
fn pin(obj: u32) -> Result<(), u32> {
    memobj_acquire_ref(MEMOBJ_KERNEL_OWNER, obj).map_err(|_| outcome::FAULT)?;
    if memobj_pin_ref(MEMOBJ_KERNEL_OWNER, obj) != Ok(true) {
        let _ = memobj_release_ref(MEMOBJ_KERNEL_OWNER, obj);
        return Err(outcome::FAULT);
    }
    Ok(())
}

fn unpin(obj: u32) {
    let _ = memobj_release_ref(MEMOBJ_KERNEL_OWNER, obj);
}

/// A memory object a guest may run on or share with the kernel: read-write,
/// whole frames of its own (no copy-on-write sharer), not reclaimable (neither swappable nor volatile), of the
/// kernel's own kinds. Its length in bytes.
fn guest_object(obj: u32) -> Result<usize, u32> {
    let d = memobj_describe_ref(obj).map_err(|_| outcome::BAD_ARGUMENT)?;
    if d.perms != MemPerms::ReadWrite
        || d.kind == MemKind::Paged
        || d.attrs & (ATTR_SWAPPABLE | ATTR_VOLATILE) != 0
        || d.cow_shared != 0
        || d.page_count == 0
    {
        return Err(outcome::BAD_ARGUMENT);
    }
    Ok(d.page_count * azos_arch::PAGE_SIZE)
}

/// Is `obj` already attached to a VM, in any role? One memory object plays one
/// role of one VM: a range of RAM mapped twice would alias the guest's own
/// memory, and the trap page or the NIC ring as RAM would let the guest write
/// the monitor's rings.
fn attached_anywhere(m: &Monitor, obj: u32) -> bool {
    m.held.iter().any(|h| {
        h.ram_objs.contains(&obj) || h.traps.is_some_and(|l| l.page == obj) || h.nic == Some(obj)
    })
}

/// Build a VM's tables. Everything this call took goes back on a failure.
fn create(m: &mut Monitor, idx: usize) -> Result<(), u32> {
    let hv = m.hv;
    if !matches!(hv.status(), HvStatus::Usable(_)) {
        return Err(outcome::UNSUPPORTED);
    }
    let vm = m.table.vm(idx).ok_or(outcome::NO_RESOURCE)?;
    if vm.state != VmState::Admitted {
        return Err(outcome::BUSY);
    }
    let mut mem = Tables;
    let s2 = hv.stage2_create(&mut mem).map_err(|_| outcome::FAULT)?;
    let vm = m.table.vm_mut(idx).ok_or(outcome::NO_RESOURCE)?;
    vm.created(s2).map_err(|_| outcome::BUSY)?;
    let vcpus = vm.vcpus as usize;
    if hv.kind() == HvKind::RiscvH {
        m.held[idx].plic = Some(Vplic::new(PLIC_DEFAULT_BASE, vcpus));
    }
    Ok(())
}

/// Give a VM's RAM and attachments back and its tables with them.
fn destroy(m: &mut Monitor, idx: usize) -> Result<(), u32> {
    let hv = m.hv;
    let vm = m.table.vm(idx).ok_or(outcome::NO_RESOURCE)?;
    if vm.state != VmState::Created || m.table.any_running(idx) {
        return Err(outcome::BUSY);
    }
    let (vmid, s2) = (vm.vmid, vm.stage2.ok_or(outcome::BUSY)?);
    let mut mem = Tables;
    let held = core::mem::take(&mut m.held[idx]);
    for (obj, seg) in held.ram_objs.iter().zip(&held.ram_segs) {
        let _ = unmap_range(hv, &s2, &mut mem, seg.gpa, seg.bytes);
        unpin(*obj);
    }
    if let Some(l) = held.traps {
        unpin(l.page);
    }
    if let Some(n) = held.nic {
        unpin(n);
    }
    hv.stage2_flush(vmid);
    hv.stage2_destroy(s2, &mut mem);
    // The table puts the VM's vCPUs back as admission made them, too: a
    // recreated VM inherits no pending interrupt and no affinity of the last.
    m.table.destroyed(idx).map_err(|_| outcome::BUSY)
}

/// Attach the memory object behind the caller's `raw` as RAM at `gpa`.
fn attach_ram(m: &mut Monitor, who: &Caller, idx: usize, raw: u32, gpa: u64) -> Result<(), u32> {
    let hv = m.hv;
    let obj = resolve::<targets::Shm>(who, raw, CapPerms::RW)?;
    if attached_anywhere(m, obj) {
        return Err(outcome::BAD_ARGUMENT);
    }
    let bytes = guest_object(obj)? as u64;
    m.table.check_ram(idx, &m.held[idx].ram_segs, gpa, bytes).map_err(|e| match e {
        RamError::NoSuchVm => outcome::NO_RESOURCE,
        RamError::NotCreated | RamError::Running => outcome::BUSY,
        RamError::Misaligned | RamError::OutOfRange | RamError::Overlap => outcome::BAD_ARGUMENT,
    })?;
    let s2 = m.table.vm(idx).and_then(|v| v.stage2).ok_or(outcome::BUSY)?;
    let held = &mut m.held[idx];
    // The records first: a refusal after the mapping would have to undo it.
    held.ram_objs.try_reserve(1).map_err(|_| outcome::FAULT)?;
    held.ram_segs.try_reserve(1).map_err(|_| outcome::FAULT)?;
    pin(obj)?;
    let src = ObjFrames { obj, frames: (bytes / azos_arch::PAGE_SIZE as u64) as usize };
    let mut mem = Tables;
    if map_frames(hv, &s2, &mut mem, gpa, &src, StagePerms { write: true, exec: true }).is_err() {
        unpin(obj);
        return Err(outcome::FAULT);
    }
    held.ram_objs.push(obj);
    held.ram_segs.push(RamSeg { gpa, bytes });
    m.table.ram_added(idx, bytes);
    Ok(())
}

/// Attach the trap page and the event port.
fn attach_traps(m: &mut Monitor, who: &Caller, idx: usize, page: u32, events: u32, key: u64) -> Result<(), u32> {
    let page = resolve::<targets::Shm>(who, page, CapPerms::RW)?;
    let port = resolve::<targets::Port>(who, events, CapPerms::WRITE)?;
    if attached_anywhere(m, page) {
        return Err(outcome::BAD_ARGUMENT);
    }
    let desc = memobj_describe_ref(page).map_err(|_| outcome::BAD_ARGUMENT)?;
    if guest_object(page)? < PAGE_BYTES || desc.attrs & ATTR_NO_KERNEL_MAP != 0 {
        return Err(outcome::BAD_ARGUMENT);
    }
    let epoch = port_live_epoch(port).map_err(|_| outcome::BAD_ARGUMENT)?;
    pin(page)?;
    if m.table.traps_attached(idx).is_err() {
        unpin(page);
        return Err(outcome::BUSY);
    }
    m.held[idx].traps = Some(Link { page, port, epoch, key });
    Ok(())
}

/// Attach the NIC ring region, if the VM's envelope allows a network.
fn attach_net(m: &mut Monitor, who: &Caller, idx: usize, raw: u32) -> Result<(), u32> {
    let ring = resolve::<targets::Shm>(who, raw, CapPerms::RW)?;
    if attached_anywhere(m, ring) {
        return Err(outcome::BAD_ARGUMENT);
    }
    guest_object(ring)?;
    let vm = m.table.vm(idx).ok_or(outcome::NO_RESOURCE)?;
    if vm.state != VmState::Created || vm.nic {
        return Err(outcome::BUSY);
    }
    if !m.table.egress_allowed(idx, Reach::Net) {
        run::record_refusal(vm.index, vm.envelope, Backend::Net, 0);
        return Err(outcome::REFUSED);
    }
    pin(ring)?;
    if m.table.nic_attached(idx).is_err() {
        unpin(ring);
        return Err(outcome::BUSY);
    }
    m.held[idx].nic = Some(ring);
    Ok(())
}

/// The `Vm` interface served for one caller.
pub struct VmServer(pub Caller);

impl VmServer {
    fn run<T: Default>(&self, class: CapPerms, f: impl FnOnce(&mut Monitor, usize) -> Out<T>) -> Out<T> {
        if let Err(o) = self.0.gate::<T>(class) {
            return o;
        }
        let Some(idx) = vm_of(self.0.badge) else { return Out::err(outcome::NO_RESOURCE) };
        with(|m| if m.table.vm(idx).is_some() { f(m, idx) } else { Out::err(outcome::NO_RESOURCE) })
            .unwrap_or_else(|| Out::err(outcome::NOT_READY))
    }
}

fn code<T: Default>(r: Result<T, u32>) -> Out<T> {
    match r {
        Ok(v) => Out::ok(v),
        Err(c) => Out::err(c),
    }
}

impl azos_devif::Vm for VmServer {
    fn state(&self) -> Out<u32> {
        self.run(CapPerms::READ, |m, i| Out::ok(m.table.vm(i).map_or(0, |v| v.state as u32)))
    }

    fn config(&self) -> Out<[u64; 5]> {
        self.run(CapPerms::READ, |m, i| {
            let Some(v) = m.table.vm(i) else { return Out::err(outcome::NO_RESOURCE) };
            Out::ok([
                v.cpus as u64,
                v.mem_mib as u64,
                v.envelope as u64 | (v.devices_len() as u64) << 8 | (v.vmid as u64) << 16,
                v.kinds,
                v.ram_base,
            ])
        })
    }

    fn create(&mut self) -> Out<()> {
        self.run(CapPerms::EXEC, |m, i| code(create(m, i)))
    }

    fn destroy(&mut self) -> Out<()> {
        self.run(CapPerms::EXEC, |m, i| code(destroy(m, i)))
    }

    fn window(&mut self, space: u32, base: u64, len: u64, device: u32) -> Out<()> {
        self.run(CapPerms::EXEC, |m, i| {
            let space = match space {
                azos_devif::vm::SPACE_MMIO => Space::Mmio,
                azos_devif::vm::SPACE_PIO => Space::Pio,
                _ => return Out::err(outcome::BAD_ARGUMENT),
            };
            let Ok(device) = u8::try_from(device) else { return Out::err(outcome::BAD_ARGUMENT) };
            match m.table.add_window(i, space, base, len, device) {
                Ok(()) => Out::ok(()),
                Err(WindowError::Full | WindowError::Running) => Out::err(outcome::BUSY),
                Err(_) => Out::err(outcome::BAD_ARGUMENT),
            }
        })
    }

    fn ram(&mut self, mem: WireCap<azos_devif::vm::GuestRam>, gpa: u64) -> Out<()> {
        let who = self.0;
        self.run(CapPerms::EXEC, |m, i| code(attach_ram(m, &who, i, mem.raw(), gpa)))
    }

    fn traps(
        &mut self,
        page: WireCap<azos_devif::vm::TrapPage>,
        events: WireCap<azos_devif::vm::EventPort>,
        key: u64,
    ) -> Out<()> {
        let who = self.0;
        self.run(CapPerms::EXEC, |m, i| code(attach_traps(m, &who, i, page.raw(), events.raw(), key)))
    }

    fn net(&mut self, ring: WireCap<azos_devif::vm::NicRing>) -> Out<()> {
        let who = self.0;
        self.run(CapPerms::EXEC, |m, i| code(attach_net(m, &who, i, ring.raw())))
    }
}

/// The `Vcpu` interface served for one caller.
pub struct VcpuServer(pub Caller);

const fn vcpu_of(badge: u32) -> Option<(usize, usize)> {
    let vm = (badge >> 8) as usize;
    if vm >= 1 && vm <= MAX_VMS { Some((vm - 1, (badge & 0xFF) as usize)) } else { None }
}

impl VcpuServer {
    fn run<T: Default>(&self, class: CapPerms, f: impl FnOnce(&mut Monitor, usize, usize) -> Out<T>) -> Out<T> {
        if let Err(o) = self.0.gate::<T>(class) {
            return o;
        }
        let Some((vm, k)) = vcpu_of(self.0.badge) else { return Out::err(outcome::NO_RESOURCE) };
        with(|m| if m.table.vcpu(vm, k).is_some() { f(m, vm, k) } else { Out::err(outcome::NO_RESOURCE) })
            .unwrap_or_else(|| Out::err(outcome::NOT_READY))
    }

    fn at(&self) -> Option<(usize, usize)> {
        vcpu_of(self.0.badge)
    }
}

/// Index of vCPU `k` of VM `vm` in the pool.
fn pool_index(m: &Monitor, vm: usize, k: usize) -> Option<usize> {
    m.table.vm(vm).map(|v| v.first_vcpu as usize + k)
}

/// End the timed sleep of a vCPU thread that waits for an answer or an
/// interrupt. Nothing happens for a thread that is not asleep: its next look
/// finds what changed.
fn wake_vcpu(vm: usize, k: usize) {
    let tid = with(|m| pool_index(m, vm, k)).flatten().map_or(0, |g| TIDS[g].load(Ordering::Acquire));
    if tid != 0 {
        azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    }
}

/// The supervisor guest-external interrupt handler's wake: the thread of the
/// vCPU that holds a guest interrupt file, whose identity arrived while the
/// vCPU waited. From interrupt context: no lock of the monitor is taken, and
/// a thread not asleep is left alone (its next entry finds the file).
pub fn wake_file_owner(key: u64) {
    if let Some(g) = HOLDERS.iter().position(|h| h.load(Ordering::Acquire) == key) {
        let tid = TIDS[g].load(Ordering::Acquire);
        if tid != 0 {
            azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
        }
    }
}

/// [`wake_vcpu`] for each vCPU (bit per index) of `mask`.
fn wake_mask(vm: usize, mask: u64) {
    for k in (0..MAX_VCPUS).filter(|k| mask >> k & 1 != 0) {
        wake_vcpu(vm, k);
    }
}

fn inject_error(e: InjectError) -> u32 {
    match e {
        InjectError::NoSuchVcpu => outcome::NO_RESOURCE,
        // An admitted VM has no tables and no RAM: nothing to raise a line in.
        InjectError::NotCreated => outcome::BUSY,
        InjectError::BadIrq => outcome::BAD_ARGUMENT,
    }
}

fn start_error(e: StartError) -> u32 {
    match e {
        StartError::NoSuchVcpu => outcome::NO_RESOURCE,
        StartError::NotCreated | StartError::NotReady | StartError::Running | StartError::NotRunning => outcome::BUSY,
        StartError::NoEntry => outcome::UNSUPPORTED,
        StartError::NoHart => outcome::REFUSED,
    }
}

/// Start vCPU `k` of VM `idx`: the table decides, the thread is made after
/// the lock is let go.
fn start(idx: usize, k: usize, pc: u64, arg: u64) -> Result<(), u32> {
    let hart = with(|m| -> Result<u8, u32> {
        let can = m.hv.can_enter();
        let hart = m.table.start(idx, k, can, m.online, m.rt, azos_drv_sys::timebase::now()).map_err(start_error)?;
        let g = pool_index(m, idx, k).ok_or(outcome::NO_RESOURCE)?;
        m.pending[g] = Some((pc, arg));
        Ok(hart)
    })
    .ok_or(outcome::NOT_READY)??;
    // The guest is untrusted: its threads run at the ordinary priority, never
    // above the tasks of the host.
    let made = azos_sched::try_task_create_affinity(
        "vcpu",
        vcpu_main,
        idx << 8 | k,
        azos_sched::DEFAULT_PRIORITY,
        hart as i8,
    );
    if made.is_none() {
        with(|m| {
            if let Some(g) = pool_index(m, idx, k) {
                m.pending[g] = None;
            }
            m.table.ended(idx, k, None, azos_drv_sys::timebase::now());
        });
        return Err(outcome::NO_RESOURCE);
    }
    Ok(())
}

impl azos_devif::Vcpu for VcpuServer {
    fn pending(&self) -> Out<u64> {
        self.run(CapPerms::READ, |m, v, k| Out::ok(m.table.vcpu(v, k).map_or(0, |c| c.pending())))
    }

    fn inject(&mut self, irq: u32) -> Out<()> {
        // Where the guest has an interrupt controller the monitor emulates,
        // `irq` is a source of it (a device's line), not a line of this vCPU:
        // the controller routes it to the contexts that enabled it.
        let mut raised = None;
        let out = self.run(CapPerms::WRITE, |m, v, k| {
            if let Some(plic) = m.held[v].plic.as_mut() {
                if m.table.vcpu(v, k).is_none() {
                    return Out::err(outcome::NO_RESOURCE);
                }
                if !(1..=azos_hv::vplic::SOURCES as u32).contains(&irq) {
                    return Out::err(outcome::BAD_ARGUMENT);
                }
                raised = Some(plic.pulse(irq as usize).raised);
                return Out::ok(());
            }
            m.table.inject(v, k, irq).map_or_else(|e| Out::err(inject_error(e)), |()| Out::ok(()))
        });
        if let (true, Some((vm, k))) = (out.is_ok(), self.at()) {
            match raised {
                // The vCPUs whose external line went up take it now.
                Some(mask) => wake_mask(vm, mask),
                // A guest parked on `wfi` takes the line now, not a slice later.
                None => wake_vcpu(vm, k),
            }
        }
        out
    }

    fn inject_msi(&mut self, id: u32) -> Out<()> {
        // The ISA names the line its entry presents as identity `id`; only a
        // machine whose guest interrupt files exist can give one (the entry
        // would otherwise refuse the vCPU).
        let Some(hv) = with(|m| m.hv) else { return Out::err(outcome::NOT_READY) };
        if hv.guest_msi_ids() == 0 {
            return Out::err(outcome::UNSUPPORTED);
        }
        let Some(line) = hv.guest_msi_line(id) else { return Out::err(outcome::BAD_ARGUMENT) };
        let out = self.run(CapPerms::WRITE, |m, v, k| {
            m.table.inject(v, k, line).map_or_else(|e| Out::err(inject_error(e)), |()| Out::ok(()))
        });
        if let (true, Some((vm, k))) = (out.is_ok(), self.at()) {
            wake_vcpu(vm, k);
        }
        out
    }

    fn set_affinity(&mut self, mask: u64) -> Out<u64> {
        self.run(CapPerms::EXEC, |m, v, k| {
            if m.pinned {
                return Out::err(outcome::REFUSED);
            }
            let effective = azos_hv::vcpu::allowed(mask, m.online, m.rt);
            if effective == 0 {
                return Out::err(outcome::BAD_ARGUMENT);
            }
            let Some(vcpu) = m.table.vcpu_mut(v, k) else { return Out::err(outcome::NO_RESOURCE) };
            vcpu.affinity = effective;
            Out::ok(effective)
        })
    }

    fn start(&mut self, pc: u64, arg: u64) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        let Some((vm, k)) = self.at() else { return Out::err(outcome::NO_RESOURCE) };
        code(start(vm, k, pc, arg))
    }

    fn stop(&mut self) -> Out<()> {
        let out = self.run(CapPerms::EXEC, |m, v, k| code(m.table.stop(v, k).map_err(start_error)));
        if let (true, Some((vm, k))) = (out.is_ok(), self.at()) {
            wake_vcpu(vm, k);
        }
        out
    }

    fn kick(&mut self) -> Out<()> {
        let out = self.run(CapPerms::WRITE, |_, _, _| Out::ok(()));
        if let (true, Some((vm, k))) = (out.is_ok(), self.at()) {
            wake_vcpu(vm, k);
        }
        out
    }

    fn state(&self) -> Out<u64> {
        self.run(CapPerms::READ, |m, v, k| {
            let Some(c) = m.table.vcpu(v, k) else { return Out::err(outcome::NO_RESOURCE) };
            let s = match c.run_state() {
                RunState::Stopped => azos_devif::vm::RUN_STOPPED,
                RunState::Running if c.is_paused() => azos_devif::vm::RUN_RUNNING | azos_devif::vm::RUN_PAUSED,
                RunState::Running => azos_devif::vm::RUN_RUNNING,
                RunState::Faulted => azos_devif::vm::RUN_FAULTED | c.fault() << 8,
            };
            Out::ok(s)
        })
    }

    fn pause(&mut self) -> Out<()> {
        let out = self.run(CapPerms::EXEC, |m, v, k| {
            let Some(c) = m.table.vcpu_mut(v, k) else { return Out::err(outcome::NO_RESOURCE) };
            code(c.request_pause().map_err(|_: PauseError| outcome::BUSY))
        });
        // A guest parked on `wfi` or waiting for an answer looks now, not a
        // slice later; one in guest mode is out at the next host tick.
        if let (true, Some((vm, k))) = (out.is_ok(), self.at()) {
            wake_vcpu(vm, k);
        }
        out
    }

    fn resume(&mut self) -> Out<()> {
        let out = self.run(CapPerms::EXEC, |m, v, k| {
            let Some(c) = m.table.vcpu_mut(v, k) else { return Out::err(outcome::NO_RESOURCE) };
            code(c.request_resume().map_err(|_: PauseError| outcome::BUSY))
        });
        if let (true, Some((vm, k))) = (out.is_ok(), self.at()) {
            wake_vcpu(vm, k);
        }
        out
    }
}

// ── the vCPU thread ─────────────────────────────────────────────────────

/// The guest's time at host time `now`, for a VM whose guest has lagged the
/// host by `lost` ticks (the time it was held, every vCPU of it: one clock).
/// The ISA keeps each vCPU's counter in step (`GuestCtx::time_skip`); this is
/// the same time for the deadline the monitor owns.
const fn guest_now(now: u64, lost: u64) -> u64 {
    now.wrapping_sub(lost)
}

/// The kernel end of a vCPU's loop ([`RunHost`]).
struct KHost {
    vm: usize,
    k: usize,
    link: Link,
    /// The monitor's event port was found gone: the thread ends as faulted.
    gone: bool,
    /// The vCPUs (bit per index) the last hypercall asked a fence of and that
    /// have not carried it out.
    awaiting: u64,
}

impl KHost {
    /// Sleep for a slice (less when the guest's timer comes due sooner), or
    /// until a `kick`, an `inject` or a `stop` ends it. A timer already due
    /// does not shorten it: the guest has it asserted and chose to wait.
    fn nap(&self) {
        use azos_drv_sys::timebase::{now, TIMER_FREQ};
        let t = now();
        let mut ticks = azos_abi::time::ns_to_ticks_ceil(WAIT_SLICE_NS, TIMER_FREQ).max(1);
        // The deadline is in the guest's ticks; a held guest has no timer.
        let due = with(|m| {
            let lost = m.table.lost(self.vm);
            m.table.vcpu(self.vm, self.k).filter(|c| !c.is_paused()).map_or(TIMER_NEVER, |c| {
                if c.timer_deadline() == TIMER_NEVER { TIMER_NEVER } else { c.timer_deadline().wrapping_add(lost) }
            })
        })
        .unwrap_or(TIMER_NEVER);
        if due != TIMER_NEVER && due > t {
            ticks = ticks.min(due - t);
        }
        azos_sched::task_block(azos_sched::WaitReason::Timer(t + ticks));
    }
}

impl RunHost for KHost {
    fn stop_requested(&mut self) -> bool {
        // Nobody to answer for the guest once the monitor's port is gone:
        // the vCPU ends, and the memory stays pinned for `destroy`.
        if port_live_epoch(self.link.port) != Ok(self.link.epoch) {
            self.gone = true;
            return true;
        }
        with(|m| m.table.vcpu(self.vm, self.k).is_none_or(|c| c.stop_requested())).unwrap_or(true)
    }

    fn pause_requested(&mut self) -> bool {
        with(|m| m.table.vcpu(self.vm, self.k).is_some_and(|c| c.pause_requested())).unwrap_or(false)
    }

    fn freeze(&mut self) {
        // The tick is read under the monitor's lock: two threads' ticks reach
        // the table in the order of their calls, so an interval never closes
        // before it opened.
        with(|m| m.table.freeze(self.vm, self.k, azos_drv_sys::timebase::now()));
    }

    fn thaw(&mut self) {
        with(|m| m.table.thaw(self.vm, self.k, azos_drv_sys::timebase::now()));
    }

    fn lost(&mut self) -> u64 {
        with(|m| m.table.lost(self.vm)).unwrap_or(0)
    }

    fn take_irqs(&mut self) -> u64 {
        // The lines raised since the last entry, and the lines that are a
        // level the monitor derives (the guest's timer, once due) against the
        // guest's time ([`guest_now`]).
        let now = azos_drv_sys::timebase::now();
        with(|m| {
            let external = m.held[self.vm].plic.as_ref().is_some_and(|p| p.line(self.k)) as u64;
            m.table.take_irqs(self.vm, self.k)
                | m.table.vcpu(self.vm, self.k).map_or(0, |c| c.levels(guest_now(now, m.table.lost(self.vm))))
                | external << EXTERNAL_LINE
        })
        .unwrap_or(0)
    }

    fn intc_mmio(&mut self, a: &MmioAccess, value: u64) -> Option<u64> {
        let (vm, k) = (self.vm, self.k);
        let (read, change) = with(|m| m.held[vm].plic.as_mut()?.serve(a, value)).flatten()?;
        // The lines that went up belong to other vCPUs' contexts as often as
        // to this one's, which reads its own on its next entry.
        wake_mask(vm, change.raised & !(1 << k));
        Some(read)
    }

    fn hypercall_host(&mut self) -> Option<&mut dyn HypercallHost> {
        Some(self)
    }

    fn take_fence(&mut self) -> Option<RemoteFence> {
        with(|m| m.table.vcpu_mut(self.vm, self.k).and_then(|c| c.take_fence())).flatten()
    }

    fn fences_outstanding(&mut self) -> bool {
        let (vm, awaiting) = (self.vm, self.awaiting);
        // A target that no longer runs has nothing left to fence.
        let left = with(|m| {
            let mut left = 0u64;
            for k in (0..MAX_VCPUS).filter(|k| awaiting >> k & 1 != 0) {
                if m.table.vcpu(vm, k).is_some_and(|c| c.run_state() == RunState::Running && c.fence_pending()) {
                    left |= 1 << k;
                }
            }
            left
        })
        .unwrap_or(0);
        self.awaiting = left;
        // A target asleep in `wfi` carries it out when woken.
        for k in (0..MAX_VCPUS).filter(|k| left >> k & 1 != 0) {
            wake_vcpu(vm, k);
        }
        left != 0
    }

    fn next_seq(&mut self, vcpu: u8) -> u32 {
        with(|m| m.table.next_seq(self.vm, vcpu as usize)).unwrap_or(0)
    }

    fn post(&mut self, t: &Trap) -> Result<(), PostError> {
        let link = self.link;
        with(|m| {
            let posted = memobj_with_span_ref(link.page, PAGE_BYTES, |base| {
                // SAFETY: `base` is the direct-map address of the trap page,
                // which the kernel pins and the region table keeps locked for
                // the length of this closure; the page is `PAGE_BYTES` long,
                // 4-aligned, and its other end follows `azos_hv::trapwire`.
                let mut page = unsafe { RawPage::new(base as *mut u8) };
                page.post_trap(t)
            });
            match posted {
                Ok(Some(Ok(()))) => {
                    // Before the lock goes: the answer must find its waiter.
                    m.table.expect(self.vm, t.vcpu as usize, t.seq);
                    Ok(())
                }
                Ok(Some(Err(Full))) => Err(PostError::Full),
                _ => Err(PostError::Gone),
            }
        })
        .unwrap_or(Err(PostError::Gone))?;
        // Every trap signals: a signal withheld because the ring was not
        // empty could be lost to a model that was about to sleep. Events that
        // pile up on a full queue are dropped and still wake.
        let ev = PortEvent { key: link.key, source_type: PORT_EVENT_RING, source_id: 0, code: 0, cpu: 0 };
        if port_queue_event_bound(link.port, link.epoch, ev) { Ok(()) } else { Err(PostError::Gone) }
    }

    fn answer(&mut self) -> Option<Completion> {
        let link = self.link;
        let got = with(|m| {
            let table = &mut m.table;
            let _ = memobj_with_span_ref(link.page, PAGE_BYTES, |base| {
                // SAFETY: as in `post`.
                let mut page = unsafe { RawPage::new(base as *mut u8) };
                table.collect(self.vm, &mut page);
            });
            table.answer(self.vm, self.k)
        })
        .flatten();
        if got.is_none() {
            self.nap();
        }
        got
    }

    fn park(&mut self) {
        self.nap();
    }

    fn yield_now(&mut self) {
        azos_sched::task_yield();
    }
}

/// What the guest's hypercalls ask of its VM. Each is one hold of the
/// monitor's lock, never across a block or a wake-up.
impl HypercallHost for KHost {
    fn vcpus(&self) -> usize {
        with(|m| m.table.vm(self.vm).map_or(0, |v| v.vcpus as usize)).unwrap_or(0)
    }

    fn vcpu_running(&self, vcpu: usize) -> bool {
        with(|m| m.table.vcpu(self.vm, vcpu).is_some_and(|c| c.run_state() == RunState::Running)).unwrap_or(false)
    }

    fn start_vcpu(&mut self, vcpu: usize, pc: u64, arg: u64) -> Result<(), VcpuStartError> {
        let in_ram = with(|m| m.held[self.vm].ram_segs.iter().any(|s| pc >= s.gpa && pc - s.gpa < s.bytes));
        if in_ram != Some(true) {
            return Err(VcpuStartError::BadAddress);
        }
        start(self.vm, vcpu, pc, arg).map_err(|o| {
            if o == outcome::BUSY { VcpuStartError::AlreadyRunning } else { VcpuStartError::Failed }
        })
    }

    fn raise_irq(&mut self, vcpu: usize, line: u32) {
        if with(|m| m.table.inject(self.vm, vcpu, line).is_ok()) == Some(true) {
            wake_vcpu(self.vm, vcpu);
        }
    }

    fn arm_timer(&mut self, vcpu: usize, deadline: u64, line: u32) {
        with(|m| m.table.vcpu_mut(self.vm, vcpu).map(|c| c.arm_timer(deadline, line)));
    }

    fn fence(&mut self, vcpu: usize, fence: RemoteFence) {
        let asked = with(|m| m.table.vcpu_mut(self.vm, vcpu).map(|c| c.request_fence(fence)).is_some());
        if asked == Some(true) {
            // Our own is carried out before our next entry; the others' are
            // waited for ([`RunHost::fences_outstanding`]).
            if vcpu != self.k {
                self.awaiting |= 1 << vcpu;
            }
            wake_vcpu(self.vm, vcpu);
        }
    }
}

/// The thread of a vCPU: `arg` is `vm << 8 | k`.
fn vcpu_main(arg: usize) {
    let (vm, k) = (arg >> 8, arg & 0xFF);
    let setup = with(|m| {
        let g = pool_index(m, vm, k)?;
        TIDS[g].store(azos_sched::current_task_tid(), Ordering::Release);
        let (pc, arg) = m.pending[g].take()?;
        let v = m.table.vm(vm)?;
        let s2 = v.stage2?;
        HOLDERS[g].store(m.hv.guest_holder_key(&s2, k as u8), Ordering::Release);
        Some(Setup {
            ctx: GuestCtx::new(s2, v.vmid, k as u8, pc, arg),
            view: RunView::new(v),
            hv: m.hv,
            link: m.held[vm].traps?,
        })
    })
    .flatten();
    let Some(Setup { mut ctx, view, hv, link }) = setup else {
        // Nothing to run (the VM was taken apart under the start): say so.
        with(|m| m.table.ended(vm, k, Some(run::fault::MONITOR_GONE << 56), azos_drv_sys::timebase::now()));
        azos_sched::task_exit()
    };
    let mut host = KHost { vm, k, link, gone: false, awaiting: 0 };
    let fault = match run::run(hv, &mut ctx, &view, &mut host) {
        Stop::Requested if !host.gone => None,
        Stop::Requested => Some(run::fault::MONITOR_GONE << 56),
        Stop::Fault(code) => Some(code),
    };
    with(|m| {
        if let Some(g) = pool_index(m, vm, k) {
            HOLDERS[g].store(0, Ordering::Release);
            TIDS[g].store(0, Ordering::Release);
        }
        m.table.ended(vm, k, fault, azos_drv_sys::timebase::now());
    });
    if fault.is_some_and(|code| code >> 56 == run::fault::SHUTDOWN) {
        // The guest ended the machine: its other vCPUs end with it.
        let n = with(|m| m.table.vm(vm).map_or(0, |v| v.vcpus as usize)).unwrap_or(0);
        for i in (0..n).filter(|&i| i != k) {
            if with(|m| m.table.stop(vm, i).is_ok()) == Some(true) {
                wake_vcpu(vm, i);
            }
        }
    }
    azos_sched::task_exit()
}
