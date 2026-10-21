// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Hypervisor::enter` on SVM: one vCPU of an AzOS guest, from the call the
//! monitor's loop makes to the exit that loop has to serve.
//!
//! [`enter`] is the whole entry: it builds the vCPU on its first call, then
//! loops *VMRUN, decode, serve* ([`super::serve`]) and returns to the caller
//! only for what needs the monitor: a device access ([`Exit::Mmio`]), a vCPU
//! with nothing to run ([`Exit::Wait`]), a physical interrupt to take
//! ([`Exit::HostInterrupt`]) and the exits nothing here serves. CPUID, MSRs,
//! `XSETBV`, the virtual APICs' registers and the empty I/O bus are answered
//! without leaving this function, which is what keeps the monitor's loop
//! (`azos_hv::run`) out of the guest's hot path: it sees an exit only when it
//! has something to do.
//!
//! # What the kernel provides
//!
//! The crate sits below the monitor and the page allocator, so what it needs
//! from them is [`VmHost`], registered once at boot ([`register_host`], from
//! `kernel/src/entry/x86_64/ext/hv.rs`): zeroed pages, the VM's vCPU count
//! and the vCPU's local APIC (the virtual LAPICs and the IOAPIC of a VM are
//! `azos_hv`'s, shared by its vCPUs under the host's lock). What it needs
//! from the CPU is [`Machine`]: `hw::Hw` on the target, a script in the host
//! tests (`tests/host/hv-tests/src/x86_enter.rs`), which run this very
//! function.
//!
//! # State
//!
//! `GuestCtx::frame` is 48 words and a vCPU is a VMCB, a host-save page, a
//! register file, the serve state and an XSAVE area. The state is therefore
//! one run of pages ([`VcpuMem`] and the FP area behind it) the entry
//! allocates from the host on a vCPU's first entry and keeps in a slot table
//! keyed by the stage-2 root and the vCPU ([`slots`]); `frame[0]` is its
//! physical address. `stage2_destroy` is the only teardown the `Hypervisor`
//! trait has, and it releases the slots of the root it destroys. A vCPU that
//! stops and starts again finds its slot and starts over in it.
//!
//! # Time, the TLB and the FP state
//!
//! * The guest's TSC is the host's (`TSC_OFFSET` 0, less the time the VM was
//!   held: `GuestCtx::time_skip`, all of it at a vCPU's first entry, so an AP
//!   started by SIPI reads the TSC the running vCPUs read). `CPUID` leaf
//!   `0x4000_0010` carries the rate and the vLAPIC timer's clock ([`VmInfo`]).
//! * The nested TLB is invalidated, through the VMCB's `TLB_CTL`, when (a) the
//!   VM's table epoch moved since this vCPU last ran ([`flush`], called by
//!   `stage2_flush`), (b) another vCPU's guest ran on this CPU since (ASID is
//!   per VM, but the guest's own translations are per vCPU), or (c) the VMCB
//!   asked for it (a start or an INIT).
//! * The guest's x87/SSE/AVX state lives in the vCPU's XSAVE area between
//!   entries, loaded under the host's `XCR0` right before the guest's `XCR0` is
//!   loaded for `VMRUN` and saved right after the host's is back, with
//!   interrupts off. The host's registers need no save: the kernel is
//!   soft-float and a kernel thread holds none (`fp.rs`).
//!
//! # Port I/O
//!
//! The permission map intercepts every port. A port nobody serves is an empty
//! bus: `IN` reads all ones and `OUT` is dropped, so a guest that probes the
//! legacy PC (the 8259s, a COM port, the PS/2 controller, PCI configuration
//! space) finds nothing and carries on instead of ending the VM. String
//! instructions are not emulated and end the vCPU, visibly.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_arch_api::{Exit, GuestCtx};

use super::apic::LocalApic;
use super::cpuid::Leaf;
use super::exit::{self, Exit as Raw};
use super::mmio::GuestMem;
use super::msr;
use super::probe::SvmCaps;
use super::serve::{Entry, Env, Served, VcpuState};
use super::svm::{ctl, icpt, off, GuestRegs, Vmcb, IOPM_BYTES, MSRPM_BYTES};
use crate::mmu;

/// The page the hardware and the permission maps are measured in.
pub const PAGE: usize = 4096;

/// VMs a table can hold (`vmid` is 1-based, so one more).
const VMS: usize = azos_limits::TOPOLOGY_MAX_GUESTS + 1;
/// Harts the per-CPU records cover.
const CPUS: usize = azos_limits::NR_CPUS;
/// Slots: the vCPUs of the pool.
const SLOTS: usize = azos_limits::HV_MAX_VCPUS as usize;

/// Most serve-and-resume rounds before the entry hands the hart back
/// ([`Exit::HostInterrupt`]): a guest that exits all the time must still let
/// the thread see a stop request.
const MAX_RESUMES: u32 = 256;

/// What an entry knows of the VM its vCPU belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmInfo {
    /// vCPUs of the VM.
    pub vcpus: u8,
    /// The guest TSC's rate in kHz (CPUID leaf `0x4000_0010`).
    pub tsc_khz: u32,
    /// The rate of the virtual APIC timer's undivided clock in kHz.
    pub apic_khz: u32,
}

/// What the kernel gives the entry. All of it is called from a vCPU thread,
/// never from an interrupt.
pub trait VmHost: Sync {
    /// `pages` contiguous zeroed 4 KiB pages, page-aligned: the physical address.
    fn alloc_pages(&self, pages: usize) -> Option<u64>;
    /// Give back what [`VmHost::alloc_pages`] returned.
    fn free_pages(&self, pa: u64, pages: usize);
    /// VM `vmid`'s facts, its interrupt controllers made if they do not exist.
    fn vm_info(&self, vmid: u16) -> Option<VmInfo>;
    /// The same for the boot CPU's first entry: the VM's interrupt controllers
    /// are rebuilt (a VM that ran before starts over).
    fn reset_vm(&self, vmid: u16) -> Option<VmInfo>;
    /// Run `f` with vCPU `vcpu`'s local APIC (and the VM's controllers behind
    /// it) held. `false` when there is no such vCPU.
    fn with_apic(&self, vmid: u16, vcpu: u8, f: &mut dyn FnMut(&mut dyn LocalApic)) -> bool;
    /// Raise device interrupt lines (bit `n`, IOAPIC pin `n`) of the VM.
    fn raise_lines(&self, vmid: u16, lines: u64);
    /// The VM's last slot is gone: drop its interrupt controllers.
    fn release_vm(&self, vmid: u16);
}

static HOST: AtomicUsize = AtomicUsize::new(0);

/// Install the kernel's [`VmHost`] (boot, once; later calls replace it).
pub fn register_host(h: &'static &'static dyn VmHost) {
    HOST.store(h as *const &'static dyn VmHost as usize, Ordering::Release);
}

/// The registered host.
pub fn host() -> Option<&'static dyn VmHost> {
    let p = HOST.load(Ordering::Acquire) as *const &'static dyn VmHost;
    // SAFETY: `register_host` stored the address of a `&'static &'static dyn
    // VmHost`, a value that lives for the whole run.
    (!p.is_null()).then(|| unsafe { *p })
}

/// What the entry needs of the CPU. `hw::Hw` is the real one.
pub trait Machine {
    /// The dense CPU number.
    fn cpu(&self) -> usize;
    fn host_tsc(&self) -> u64;
    /// `ticks` of the host's timebase as TSC cycles.
    fn ticks_to_tsc(&self, ticks: u64) -> u64;
    /// The host's `CPUID`, limited to what the guest's XSAVE area can hold.
    fn host_cpuid(&self, leaf: u32, sub: u32) -> Leaf;
    fn svm_caps(&self) -> SvmCaps;
    /// Bytes of the guest FP area.
    fn fp_bytes(&self) -> usize;
    /// Pages the backend keeps per vCPU after the FP area ([`extra_offset`]):
    /// the VMCS and its side page on VMX, none on SVM. Zeroed when the vCPU
    /// is built.
    fn extra_pages(&self) -> usize {
        0
    }
    /// Copy host-physical memory; `false` if it is not RAM.
    fn read_phys(&self, pa: u64, buf: &mut [u8]) -> bool;
    /// Where physical page `pa` is mapped for the entry.
    fn map(&self, pa: u64) -> *mut u8;
    /// Enter the guest once and return after its `#VMEXIT`: interrupts off,
    /// SVM enabled on this CPU, the FP state and `XCR0` swapped around it.
    /// `cpu` is the CPU the entry looked at ([`Machine::cpu`]); a thread that
    /// was moved since does not enter ([`Ran::Moved`]). With interrupts off
    /// and the thread known to be on `cpu`, right before the entry, the
    /// implementation calls [`Claim::enter`], and [`Claim::leave`] right after
    /// the exit and before the interrupt flag is back: the guest is published
    /// as running on the CPU only while the thread cannot be preempted or
    /// moved, which is what [`flush`] relies on to wait for it.
    fn vmrun(&mut self, v: &mut VcpuMem, fp: *mut u8, guest_xcr0: u64, cpu: usize, claim: &Claim) -> Ran;
}

/// What [`Machine::vmrun`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ran {
    /// The guest ran and exited.
    Done,
    /// The thread is on another CPU than the one the entry prepared for: nothing
    /// ran, prepare again.
    Moved,
    /// SVM could not be enabled on this CPU.
    NoSvm,
}

// ── the state of a vCPU ─────────────────────────────────────────────────

/// What the entry keeps per vCPU besides the VMCB.
#[repr(C)]
pub struct Run {
    pub regs: GuestRegs,
    pub st: VcpuState,
    /// Physical address of the [`VcpuMem`] this is part of.
    pub pa: u64,
    pub asid: u32,
    /// The VM's table epoch the nested TLB is flushed for.
    pub epoch: u32,
    pub vmid: u16,
}

/// The pages of a vCPU: the VMCB, the page `VMRUN` parks the host in, and
/// [`Run`]. The guest FP area follows in memory ([`fp_offset`]).
#[repr(C, align(4096))]
pub struct VcpuMem {
    pub vmcb: Vmcb,
    pub host_save: [u8; PAGE],
    pub run: Run,
}

const _: () = assert!(core::mem::size_of::<Run>() <= PAGE);
const _: () = assert!(core::mem::size_of::<VcpuMem>() % PAGE == 0);
const _: () = assert!(core::mem::offset_of!(VcpuMem, vmcb) == 0);
const _: () = assert!(core::mem::offset_of!(VcpuMem, host_save) == PAGE);

/// Where the FP area starts, bytes from the start of the vCPU's pages.
pub const fn fp_offset() -> usize {
    core::mem::size_of::<VcpuMem>()
}

/// Pages a vCPU takes with an FP area of `fp_bytes`.
pub const fn vcpu_pages(fp_bytes: usize) -> usize {
    (fp_offset() + fp_bytes).div_ceil(PAGE)
}

/// Where the backend's own pages start, bytes from the start of the vCPU's
/// pages: the first page boundary after the FP area.
pub const fn extra_offset(fp_bytes: usize) -> usize {
    (fp_offset() + fp_bytes).next_multiple_of(PAGE)
}

impl VcpuMem {
    pub fn vmcb_pa(&self) -> u64 {
        self.run.pa
    }
    pub fn host_save_pa(&self) -> u64 {
        self.run.pa + PAGE as u64
    }
}

// ── the slot table ──────────────────────────────────────────────────────

/// A spin lock for the slot table: short, never held across an allocation.
struct Locked<T> {
    held: AtomicBool,
    v: UnsafeCell<T>,
}

// SAFETY: `with` gives one holder at a time access to `v`.
unsafe impl<T: Send> Sync for Locked<T> {}

impl<T> Locked<T> {
    const fn new(v: T) -> Locked<T> {
        Locked { held: AtomicBool::new(false), v: UnsafeCell::new(v) }
    }

    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self.held.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: the flag is ours until the store below.
        let r = f(unsafe { &mut *self.v.get() });
        self.held.store(false, Ordering::Release);
        r
    }
}

#[derive(Clone, Copy)]
struct Slot {
    /// The stage-2 root of the VM; 0 = free.
    root: u64,
    vmid: u16,
    vcpu: u8,
    pa: u64,
    pages: u32,
}

const FREE: Slot = Slot { root: 0, vmid: 0, vcpu: 0, pa: 0, pages: 0 };

static TABLE: Locked<[Slot; SLOTS]> = Locked::new([FREE; SLOTS]);

/// The permission maps every vCPU shares: IOPM then MSRPM, physical address.
static PERMS: AtomicU64 = AtomicU64::new(0);
static PERMS_LOCK: Locked<()> = Locked::new(());

/// Which slot is `(root, vcpu)`: its physical address and size.
fn slot_find(root: u64, vcpu: u8) -> Option<(u64, u32)> {
    TABLE.with(|t| t.iter().find(|s| s.root == root && s.vcpu == vcpu).map(|s| (s.pa, s.pages)))
}

/// Take the slot of `(root, vcpu)`, the pages allocated if it has none.
fn slot_claim(host: &dyn VmHost, root: u64, vmid: u16, vcpu: u8, pages: usize) -> Option<u64> {
    if let Some((pa, have)) = slot_find(root, vcpu) {
        return (have as usize >= pages).then_some(pa);
    }
    let pa = host.alloc_pages(pages)?;
    let installed = TABLE.with(|t| {
        if t.iter().any(|s| s.root == root && s.vcpu == vcpu) {
            return false;
        }
        match t.iter_mut().find(|s| s.root == 0) {
            Some(s) => {
                *s = Slot { root, vmid, vcpu, pa, pages: pages as u32 };
                true
            }
            None => false,
        }
    });
    if !installed {
        host.free_pages(pa, pages);
        // Another claim of the same vCPU won: use its slot.
        return slot_find(root, vcpu).and_then(|(p, have)| (have as usize >= pages).then_some(p));
    }
    Some(pa)
}

/// Give back the slots of the VM whose stage-2 root is `root`, and the VM's
/// interrupt controllers with them. Called by `stage2_destroy`.
pub fn slots_release(host: &dyn VmHost, root: u64) {
    let mut gone = [FREE; SLOTS];
    let n = TABLE.with(|t| {
        let mut n = 0;
        for s in t.iter_mut().filter(|s| s.root == root) {
            gone[n] = *s;
            n += 1;
            *s = FREE;
        }
        n
    });
    for s in &gone[..n] {
        host.free_pages(s.pa, s.pages as usize);
    }
    if let Some(s) = gone[..n].first() {
        host.release_vm(s.vmid);
    }
}

/// The IOPM and MSRPM, built on first use and shared: every port exits and
/// every MSR not in [`msr::PASSTHROUGH`] does, whatever the VM.
fn perms(host: &dyn VmHost, m: &dyn Machine) -> Option<(u64, u64)> {
    const PAGES: usize = (IOPM_BYTES + MSRPM_BYTES) / PAGE;
    let mut pa = PERMS.load(Ordering::Acquire);
    if pa == 0 {
        pa = PERMS_LOCK.with(|()| {
            let cur = PERMS.load(Ordering::Acquire);
            if cur != 0 {
                return cur;
            }
            let Some(pa) = host.alloc_pages(PAGES) else { return 0 };
            let p = m.map(pa);
            // SAFETY: `PAGES` pages the host just gave, mapped by the machine.
            let (io, ms) = unsafe {
                (
                    core::slice::from_raw_parts_mut(p, IOPM_BYTES),
                    &mut *(p.add(IOPM_BYTES) as *mut [u8; MSRPM_BYTES]),
                )
            };
            io.fill(0xFF);
            msr::build_msrpm(ms);
            PERMS.store(pa, Ordering::Release);
            pa
        });
    }
    (pa != 0).then_some((pa, pa + IOPM_BYTES as u64))
}

// ── the nested TLB ──────────────────────────────────────────────────────

static EPOCH: [AtomicU32; VMS] = [const { AtomicU32::new(0) }; VMS];
/// Per CPU: the VM (`vmid`) whose guest is running on it, 0 for none.
static RUNNING: [AtomicU32; CPUS] = [const { AtomicU32::new(0) }; CPUS];
/// Per CPU: how many guest entries it has made (the flush waits for one).
static ENTRIES: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
/// Per CPU: the VMCB whose guest ran on it last.
static LAST: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];

/// Invalidate VM `vmid`'s nested translations everywhere: the epoch moves, so
/// every vCPU flushes its ASID before it next enters, and each CPU that has a
/// guest of the VM running is made to leave it (`kick`: a physical interrupt
/// ends the entry) and waited for, so no stale translation outlives the call.
pub fn flush(vmid: u16, me: usize, kick: &mut dyn FnMut(usize)) {
    let Some(e) = EPOCH.get(vmid as usize) else { return };
    e.fetch_add(1, Ordering::SeqCst);
    for cpu in (0..CPUS).filter(|&c| c != me) {
        if RUNNING[cpu].load(Ordering::SeqCst) != vmid as u32 {
            continue;
        }
        let seen = ENTRIES[cpu].load(Ordering::SeqCst);
        kick(cpu);
        let mut spins = 0u32;
        while RUNNING[cpu].load(Ordering::SeqCst) == vmid as u32 && ENTRIES[cpu].load(Ordering::SeqCst) == seen {
            core::hint::spin_loop();
            spins += 1;
            // A physical interrupt ends a guest's entry whatever it does, so this
            // is microseconds. A CPU that does not leave is a bug, and the frame
            // the caller is about to reuse may still be mapped by it: stop, loudly.
            assert!(spins < 1_000_000_000, "x86 hv: CPU {cpu} did not leave the guest of VM {vmid} after the flush IPI");
        }
    }
}

/// What one entry publishes about itself, and the nested-TLB decision that
/// has to be made together with it.
///
/// [`flush`] waits for a CPU to leave a guest only if it sees the guest as
/// running there, so the publication must hold only while a guest can run:
/// after interrupts are off and the thread is confirmed on the CPU (a thread
/// that was preempted or moved with the claim made would leave the CPU marked
/// until it is scheduled again, and the flush would spin on it). The epoch is
/// read after the publication for the same reason: a flush either sees the
/// claim and waits, or its epoch move is seen here and the entry flushes.
pub struct Claim {
    vmid: u16,
    /// Physical address of the vCPU's [`VcpuMem`].
    pa: u64,
    /// The `TLB_CTL` value that flushes this VM's ASID (everything on a CPU
    /// that cannot flush by ASID).
    flush_kind: u8,
}

impl Claim {
    /// Publish the guest as running on `cpu` and decide its nested TLB: the
    /// VM's table epoch moved since this vCPU last ran ([`flush`]) or another
    /// vCPU's guest ran here since (ASID is per VM, but the guest's own
    /// translations are per vCPU). A flush a start or an INIT asked for is
    /// already in `TLB_CTL` and is only strengthened.
    pub fn enter(&self, v: &mut VcpuMem, cpu: usize) {
        RUNNING[cpu % CPUS].store(self.vmid as u32, Ordering::SeqCst);
        ENTRIES[cpu % CPUS].fetch_add(1, Ordering::SeqCst);
        let mut tlb = v.vmcb.rd8(off::TLB_CTL);
        let epoch = EPOCH[self.vmid as usize].load(Ordering::SeqCst);
        if v.run.epoch != epoch {
            v.run.epoch = epoch;
            tlb = stronger(tlb, self.flush_kind);
        }
        if LAST[cpu % CPUS].swap(self.pa, Ordering::SeqCst) != self.pa {
            tlb = stronger(tlb, self.flush_kind);
        }
        v.vmcb.wr32(off::TLB_CTL, tlb as u32);
    }

    /// The guest is out: `cpu` no longer runs one. Before interrupts are on
    /// again, so a preemption cannot leave it published.
    pub fn leave(&self, cpu: usize) {
        RUNNING[cpu % CPUS].store(0, Ordering::SeqCst);
    }
}

// ── guest memory ────────────────────────────────────────────────────────

/// The table words of the nested tables, read through the machine.
struct Tables<'a>(&'a dyn Machine);

impl mmu::TableMem for Tables<'_> {
    fn read(&self, table: usize, idx: usize) -> u64 {
        let mut b = [0u8; 8];
        if self.0.read_phys(table as u64 + idx as u64 * 8, &mut b) { u64::from_le_bytes(b) } else { 0 }
    }
    fn write(&mut self, _table: usize, _idx: usize, _word: u64) {}
    fn alloc_table(&mut self) -> Option<usize> {
        None
    }
}

/// Guest RAM through the nested tables.
struct Ram<'a> {
    m: &'a dyn Machine,
    root: u64,
    levels: usize,
}

impl GuestMem for Ram<'_> {
    fn read(&self, gpa: u64, buf: &mut [u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            let at = gpa + done as u64;
            let Some(l) = mmu::translate(&Tables(self.m), self.root as usize, self.levels, at as usize) else {
                return false;
            };
            let in_page = PAGE - (at as usize & (PAGE - 1));
            let n = in_page.min(buf.len() - done);
            if !self.m.read_phys(l.phys as u64, &mut buf[done..done + n]) {
                return false;
            }
            done += n;
        }
        true
    }
}

// ── the entry ───────────────────────────────────────────────────────────

/// The `CPUID.1:EAX` the guest's INIT-started processors find in `EDX`.
fn signature(m: &dyn Machine) -> u32 {
    m.host_cpuid(1, 0).eax
}

/// Build the vCPU of `ctx` on its first entry: its pages, its VMCB, its state.
fn build(m: &mut dyn Machine, host: &dyn VmHost, ctx: &mut GuestCtx) -> Result<(), Exit> {
    let bad = Exit::InvalidState;
    if ctx.vmid == 0 || ctx.vmid as usize >= VMS {
        return Err(bad);
    }
    let caps = m.svm_caps();
    let asid = ctx.vmid as u32;
    if asid >= caps.nasid {
        return Err(bad);
    }
    let info = if ctx.vcpu == 0 { host.reset_vm(ctx.vmid) } else { host.vm_info(ctx.vmid) }.ok_or(bad)?;
    if ctx.vcpu >= info.vcpus {
        return Err(bad);
    }
    let (iopm, msrpm) = perms(host, m).ok_or(bad)?;
    let pages = vcpu_pages(extra_offset(m.fp_bytes()) - fp_offset() + m.extra_pages() * PAGE);
    let pa = slot_claim(host, ctx.s2.root, ctx.vmid, ctx.vcpu, pages).ok_or(bad)?;
    let p = m.map(pa);
    // SAFETY: `pages` pages the slot owns, mapped by the machine; the slot is
    // this vCPU's alone (the monitor starts a vCPU once), so nothing else
    // touches it.
    let v = unsafe { &mut *(p as *mut VcpuMem) };
    // SAFETY: the FP area is the rest of the same run of pages.
    let fp = unsafe { core::slice::from_raw_parts_mut(p.add(fp_offset()), m.fp_bytes()) };
    crate::fp::init_area(fp);
    // SAFETY: the backend's pages are the end of the same run of pages.
    unsafe { core::ptr::write_bytes(p.add(extra_offset(m.fp_bytes())), 0, m.extra_pages() * PAGE) };

    // Zero the VMCB and the host-save page (a slot kept from an earlier start
    // holds that run's); `Run` is written whole.
    v.vmcb = Vmcb::new();
    v.host_save.fill(0);
    let mut regs = GuestRegs::default();
    if ctx.vcpu == 0 {
        v.vmcb.init_pvh(&mut regs, ctx.entry_pc, ctx.entry_arg, asid).map_err(|_| bad)?;
    } else {
        // Waits for its startup IPI; the state it runs in is made then.
        v.vmcb.init_real_mode(0, asid);
    }
    // What `Vmcb::intercept_minimum` leaves to the caller: CPUID is served
    // here, and a physical NMI must end the entry, not be taken by the guest.
    v.vmcb.or32(off::INTERCEPT_W3, icpt::CPUID | icpt::NMI);
    v.vmcb.enable_nested_paging(ctx.s2.root);
    v.vmcb.set_iopm(iopm);
    v.vmcb.set_msrpm(msrpm);
    let mut st = VcpuState::new(ctx.vcpu as u32, info.vcpus as u32, asid);
    st.nrips = caps.nrips;
    st.signature = signature(m);
    st.tsc_khz = info.tsc_khz;
    st.apic_khz = info.apic_khz;
    v.run = Run {
        regs,
        st,
        pa,
        asid,
        epoch: EPOCH[ctx.vmid as usize].load(Ordering::SeqCst),
        vmid: ctx.vmid,
    };
    ctx.frame[0] = pa;
    Ok(())
}

/// The decoded exit the monitor's loop switches on, for one `exit::Exit`
/// the service did not answer (the same table as `Hypervisor::decode_exit`).
pub fn common(e: Raw) -> Exit {
    use azos_arch_api::{PioAccess, StageAccess};
    match e {
        Raw::NestedFault(f) => Exit::Fault {
            gpa: f.gpa,
            access: if f.exec {
                StageAccess::Exec
            } else if f.write {
                StageAccess::Write
            } else {
                StageAccess::Read
            },
        },
        Raw::Io(i) => Exit::Pio(PioAccess { port: i.port, size: i.size, write: i.write, string: i.string, rep: i.rep }),
        Raw::Cpuid => Exit::Cpuid,
        Raw::Msr { write } => Exit::SysReg { write },
        Raw::Halt => Exit::Wait,
        Raw::Xsetbv => Exit::Other(super::svm::code::XSETBV),
        Raw::IntWindow => Exit::Other(super::svm::code::VINTR),
        Raw::Interrupt | Raw::Nmi => Exit::HostInterrupt,
        Raw::Hypercall => Exit::Hypercall,
        Raw::Shutdown => Exit::Shutdown,
        Raw::InvalidState => Exit::InvalidState,
        Raw::Other(c) => Exit::Other(c),
    }
}

/// The stronger of two `TLB_CTL` values: flush everything beats flush the
/// ASID beats nothing (the encodings do not order that way).
fn stronger(a: u8, b: u8) -> u8 {
    if a == ctl::TLB_FLUSH_ALL || b == ctl::TLB_FLUSH_ALL { ctl::TLB_FLUSH_ALL } else { a.max(b) }
}

/// Answer an `IN` or `OUT` nobody serves like an empty bus. `false` for the
/// string forms, which are not emulated.
fn empty_bus(vmcb: &mut Vmcb, io: &exit::IoAccess) -> bool {
    if io.string {
        return false;
    }
    if !io.write {
        let rax = vmcb.rd64(off::RAX);
        let v = match io.size {
            1 => rax | 0xFF,
            2 => rax | 0xFFFF,
            // A 32-bit write to EAX clears the upper half.
            _ => 0xFFFF_FFFF,
        };
        vmcb.wr64(off::RAX, v);
    }
    vmcb.wr64(off::RIP, io.next_rip);
    true
}

/// Run the vCPU of `ctx` until something needs the monitor; see the module
/// docs. `host` is the kernel's, `m` the CPU.
pub fn enter(m: &mut dyn Machine, host: &dyn VmHost, ctx: &mut GuestCtx) -> Exit {
    if ctx.frame[0] == 0 {
        if let Err(e) = build(m, host, ctx) {
            return e;
        }
    }
    let pa = ctx.frame[0];
    let p = m.map(pa);
    // SAFETY: `frame[0]` is the address `build` set: the slot's pages, the
    // vCPU's alone for as long as the vCPU runs.
    let v = unsafe { &mut *(p as *mut VcpuMem) };
    // SAFETY: the FP area follows the run of `VcpuMem`.
    let fp = unsafe { p.add(fp_offset()) };
    let caps = m.svm_caps();
    let (vmid, vcpu) = (ctx.vmid, ctx.vcpu);
    let (root, levels) = (ctx.s2.root, ctx.s2.aux as usize);

    // The device access the monitor answered since the last entry.
    if let Some(done) = ctx.completed.take() {
        let VcpuMem { vmcb, run, .. } = &mut *v;
        run.st.finish_mmio(vmcb, &mut run.regs, done.value);
    }
    if ctx.irqs != 0 {
        host.raise_lines(vmid, core::mem::take(&mut ctx.irqs));
    }
    // The time the VM was held is not the guest's: its TSC, and the APIC
    // timer's deadline against it, resume where they stopped. A new vCPU gets
    // all of it here, whatever it was built with. Added to the offset the
    // guest may have written itself (`WRMSR` of the TSC).
    if ctx.time_skip != 0 {
        let held = m.ticks_to_tsc(ctx.time_skip);
        let offset = v.vmcb.rd64(off::TSC_OFFSET);
        v.vmcb.wr64(off::TSC_OFFSET, offset.wrapping_sub(held));
    }

    for _ in 0..MAX_RESUMES {
        // Fire the timer, take the start events, inject.
        let mut entry = None;
        let ok = host.with_apic(vmid, vcpu, &mut |apic| {
            let ram = Ram { m: &*m, root, levels };
            let cpuid = |l, s| m.host_cpuid(l, s);
            let mut env = Env { host_cpuid: &cpuid, apic, mem: &ram, host_tsc: m.host_tsc() };
            let VcpuMem { vmcb, run, .. } = &mut *v;
            entry = Some(run.st.before_entry(vmcb, &mut run.regs, &mut env));
        });
        if !ok {
            return Exit::InvalidState;
        }
        if entry == Some(Entry::WaitSipi) {
            return Exit::Wait;
        }

        if v.vmcb.check(caps.nasid).is_err() {
            return Exit::InvalidState;
        }
        let cpu = m.cpu();
        let claim = Claim { vmid, pa, flush_kind: if caps.flush_by_asid { ctl::TLB_FLUSH_ASID } else { ctl::TLB_FLUSH_ALL } };

        let xcr0 = v.run.st.xcr0();
        let ran = m.vmrun(v, fp, xcr0, cpu, &claim);
        match ran {
            Ran::Done => v.vmcb.wr32(off::TLB_CTL, ctl::TLB_DO_NOTHING as u32),
            // The flush asked for stays in the VMCB for the next try.
            Ran::Moved => continue,
            Ran::NoSvm => return Exit::InvalidState,
        }

        let raw = exit::svm(
            v.vmcb.rd64(off::EXIT_CODE),
            v.vmcb.rd64(off::EXIT_INFO_1),
            v.vmcb.rd64(off::EXIT_INFO_2),
        );
        if matches!(raw, Raw::Interrupt | Raw::Nmi) {
            // Not served (no APIC lock for a tick), but an event the guest was
            // taking when the interrupt came is not lost.
            v.vmcb.requeue_exit_event();
            return Exit::HostInterrupt;
        }
        let mut served = None;
        let ok = host.with_apic(vmid, vcpu, &mut |apic| {
            let ram = Ram { m: &*m, root, levels };
            let cpuid = |l, s| m.host_cpuid(l, s);
            let mut env = Env { host_cpuid: &cpuid, apic, mem: &ram, host_tsc: m.host_tsc() };
            let VcpuMem { vmcb, run, .. } = &mut *v;
            served = Some(run.st.serve(raw, vmcb, &mut run.regs, &mut env));
        });
        if !ok {
            return Exit::InvalidState;
        }
        match served {
            Some(Served::Resume) => {}
            Some(Served::Wait) => return Exit::Wait,
            Some(Served::HostInterrupt) => return Exit::HostInterrupt,
            Some(Served::Shutdown) => return Exit::Shutdown,
            Some(Served::InvalidState) | None => return Exit::InvalidState,
            Some(Served::Mmio { access, value }) => {
                ctx.mmio_value = value;
                return Exit::Mmio(access);
            }
            Some(Served::Unserved(Raw::Io(io))) if empty_bus(&mut v.vmcb, &io) => {}
            Some(Served::Unserved(e)) => return common(e),
        }
    }
    Exit::HostInterrupt
}
