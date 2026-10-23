// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `VMMD.ELF`: the AzOS virtual-machine monitor, ring 3 (hypervisor plan H1).
//!
//! The kernel's hypervisor core owns what only the kernel can: the guest's
//! stage-2 tables and the vCPU threads. Everything a guest *does* with a
//! device is served here, by a program whose row is its whole authority. **The
//! guest holds no warrant; vmmd's backends do**: the disk is a file opened
//! through the `Cap<Dir>` of this row, the console is the console this task
//! writes, the NIC is a ring pair, so what a guest can cause is what these
//! handles can cause, through the same gate and the same record as any native
//! task (and the kernel holds the guest to its envelope at the trap, before
//! any of this sees a store).
//!
//! The device models are pure and tested on the host (`tests/host/vmmd-tests`):
//! `mmio` (the virtio-mmio transport), `virtq` (the split queue, which trusts
//! nothing the guest wrote), `blk`, `net`, `console`, the trap protocol
//! (`trap`, over `azos_hv::trapwire`), the per-VM step (`model`), the
//! description of the machine a guest boots into (`dtb`, `pvh`, `loader`,
//! `life`) and the control plane (`ctl`). This file is the loop around them.
//!
//! # What this program does
//!
//! 1. Finds `vm.0` and its vCPUs (an endpoint `vcpu.0.k` for each of the
//!    row's CPUs), reads `Vm::config`: the row's CPUs, RAM, **which backend
//!    sits at which device index**, and where RAM starts. A VM already created
//!    was left so by a monitor that ended: it is stopped and given back
//!    (`Vm::destroy`) first.
//! 2. Serves the `VmCtl` interface (`azos_devif::vmctl`) on `endpoint.vmctl`,
//!    the endpoint its row serves and the name server lends to the rows that
//!    import `vmctl`: a *service thread* accepts each call and hands it to
//!    this loop through the mailbox (`ctl::Mailbox`), which runs it between
//!    two passes. Nothing else runs on that thread: the machine's state is
//!    this loop's alone.
//! 3. Builds a guest when asked (`ctl::Control::create`, the [`Monitor`] as
//!    its host): the VM (the stage-2 tables), its RAM, a memory object at a
//!    time (a memory object holds at most [`CHUNK_PAGES`] pages), mapped
//!    into this task and attached with `Vm::ram` (`guest::SegRam` is then the
//!    guest's memory as the models see it); the trap page and an event port,
//!    attached with `Vm::traps`; one MMIO window per backend it has a model
//!    for (`Vm::window`); the NIC's ring region (`Vm::net`, which the VM's
//!    envelope may refuse: the guest then has no NIC). The RAM, the trap page
//!    and the NIC ring are charged to this task's Domain (the kernel only
//!    pins them until `destroy`), so the `mem_pages` of this task's row must
//!    cover the guest's `mem_mib`: the build refuses the guest when it does
//!    not. A task holds at most `USER_WINDOW_RANGES` (16) mappings, its other
//!    regions included, so less than 4 MiB of guest RAM is mapped; past that
//!    the RAM is partial ("guest RAM is partial") and no device model works.
//! 4. Loads the kernel (an ELF64 executable of the host's ISA, read beneath
//!    `/fat/VM`), puts the description of the machine next to it (a device
//!    tree on riscv64 and aarch64, `dtb`; a PVH start_info on x86_64, `pvh`;
//!    the owner's command line is `/fat/VM/CMDLINE`) and, when asked, starts
//!    vCPU 0 at the kernel's entry with that description's address in the
//!    boot register (`life::prepare`, `life::boot`, `Vcpu::start`; refused
//!    with `UNSUPPORTED` where the ISA's guest entry is not wired). The other
//!    vCPUs wait for the guest to ask for them (see `life`). At start-up the
//!    monitor makes the same calls for `/fat/VM/KERNEL.ELF`, if the volume
//!    has one (`ctl::Control::autostart`).
//! 5. Serves: sleeps on the event port (with a deadline, for the devices'
//!    host side), answers each trap on the completion ring, **kicks** the
//!    vCPUs it answered and raises the interrupt lines the answers raised
//!    (`Vcpu::inject`: a device's line goes to vCPU 0 until the guest has an
//!    interrupt controller to route it).
//! 6. Looks at the started vCPUs every [`WATCH_MS`]: one that left (a shutdown
//!    or a fault the kernel serves nothing for) ends the guest, so the others
//!    are stopped (`Vcpu::stop`) and the VM is given back with everything this
//!    task made for it (memory objects included): the row is free again for
//!    the next `create`.
//!
//! Not here: the guest firmware interface (SBI, PSCI, INIT-SIPI) and the
//! interrupt controller a booting kernel programs, so a guest that does more
//! than poke its devices faults its vCPU, visibly.
//!
//! * The disk is a file read in order (the typed file calls have no offset),
//!   so a random access costs the distance to it; `store` meters that work
//!   per pass so it never stalls the loop for long, and a positional read is
//!   what makes it cheap.
//! * The NIC's other end is not found anywhere yet: no registry of virtual
//!   interfaces exists. The ring pair itself is real and tested joined to the
//!   virtio-net device, and the kernel holds the region once attached.
//!
//! The guest's console is not a termd session; see `console` for why, and for
//! what stands in its place. While a tool holds the console ring
//! (`VmCtl::console`) the output goes there instead (`ctl::Sink`).

#![no_std]
#![no_main]

mod blk;
mod console;
mod ctl;
mod dtb;
mod guest;
mod life;
mod loader;
mod mmio;
mod model;
mod net;
mod pvh;
mod ringlink;
mod store;
mod trap;
mod virtq;
/// The wire form of the trap rings: the kernel's file, included here so the
/// two ends cannot drift (`azos_hv::trapwire`). This end uses its half (the
/// kernel encodes traps, vmmd decodes them).
#[allow(dead_code)]
#[path = "../../../../crates/core/hv/src/trapwire.rs"]
mod wire;

use azos_libsys as sys;
use blk::{Blk, IoError};
use console::{Console, Guarded, Term};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};
use ctl::{Control, Fail, Host, Limited, Mailbox, Retired, Row, Sink, Wake};
use guest::{GuestMem, SegRam};
use life::{Boot, Cpu, Entry, Setup, Watch, VCPUS};
use model::{Kind, Machine};
use net::Net;
use ringlink::RingLink;
use store::{SeqFile, SeqStore};
use azos_devif::vmctl::{self, cause};
use azos_devif::{MsgDesc, VmCtlIdl};
use sys::dev::{Cap, Ep, VcpuCall, VcpuClient, VmCall, VmClient};
use trap::Rings;

/// The guest's disk image, on the volume.
const DISK: &[u8] = b"/fat/VM/DISK.IMG\0";
/// Where a guest's kernel is read from: the guest directory, beneath the
/// root directory of this row. A request names a file beneath it
/// (`ctl::image_ok`).
const GUEST_DIR: &[u8] = b"/fat/VM/";
/// The kernel's command line: one line of text, optional.
const CMDLINE: &[u8] = b"/fat/VM/CMDLINE\0";
/// The room the kernel loader reads through and the machine description is
/// built in (`life::prepare`): in the image rather than on the 16 KiB stack.
static SCRATCH: Single<[u8; life::SCRATCH_BYTES]> = Single::new([0; life::SCRATCH_BYTES]);
/// The longest command line kept.
const CMDLINE_MAX: usize = 256;
/// The key the kernel puts on the events it posts to the port: any event of
/// this port means "the trap ring has an entry".
const EVENT_KEY: u64 = 0x564D_4D44;
/// The key of the event the service thread posts to wake the loop for a call.
const CTL_KEY: u64 = 0x564D_4354;
/// Pages of the memory objects the guest's RAM is made of: the most a memory
/// object holds (`azos_ipc::memobj::MAX_MEMOBJ_PAGES`).
const CHUNK_PAGES: usize = 64;
/// The guest NIC's address (locally administered, unicast).
const MAC: [u8; 6] = [0x02, 0x41, 0x7A, 0x4F, 0x53, 0x01];
/// Milliseconds between two looks at the devices' host side, once the guest's
/// RAM can be reached. A trap wakes the wait sooner.
const POLL_MS: u64 = 10;
/// The same while it cannot, or while there is no guest: nothing can be in
/// flight, and a call to the control plane wakes the wait.
const IDLE_MS: u64 = 1000;
/// The same while a request waits for its next share of the store's budget.
const BUSY_MS: u64 = 1;
/// Milliseconds between two looks at whether the guest's vCPUs still run.
const WATCH_MS: u64 = 100;
/// How long one wait for the vCPU threads to end lasts, and how many of them
/// a teardown makes: a thread ends at its next exit, which is a slice of the
/// kernel's loop away.
const STOP_SLICE_MS: u64 = 10;
const STOP_SLICES: u32 = 100;
/// Memory objects this task holds for one guest: its RAM (at most
/// `guest::MAX_SEGS`), the trap page and the NIC ring.
const HELD_MAX: usize = guest::MAX_SEGS + 2;
/// Bytes of the service thread's stack.
const CTL_STACK_BYTES: usize = 8192;

// The state words `life` tests against are the interface's.
const _: () = assert!(life::RUN_RUNNING == sys::dev::vm::RUN_RUNNING && life::RUN_FAULTED == sys::dev::vm::RUN_FAULTED);
// The console ring's region holds the ring the lease promises.
const _: () = assert!(
    azos_rings::region::SpscStream::bytes(vmctl::CONSOLE_RING_CAP) <= vmctl::CONSOLE_RING_PAGES as usize * sys::PAGE_SIZE
);

const O_RDONLY: u64 = 0;
const O_RDWR: u64 = 2;

/// A value only one thread touches (the monitor's loop): the guest's state is
/// too large for the task's stack, so it lives in the image.
struct Single<T>(UnsafeCell<T>);

// SAFETY: every use is on the loop's thread (see `Single::get`); the service
// thread touches only `MAILBOX` and `PORT`.
unsafe impl<T> Sync for Single<T> {}

impl<T> Single<T> {
    const fn new(v: T) -> Single<T> {
        Single(UnsafeCell::new(v))
    }

    /// The value.
    ///
    /// # Safety
    /// The caller is the monitor's loop thread and holds no other reference
    /// to the value.
    #[allow(clippy::mut_from_ref)]
    unsafe fn get(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }
}

/// This task's own console, which [`Guarded`] puts the guest's output on.
struct Out;

impl Term for Out {
    fn write(&mut self, bytes: &[u8]) {
        let _ = sys::console_write(sys::STDOUT, bytes);
    }

    /// Nothing lends a guest the console's input (see `console`).
    fn read(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
}

/// The guest's disk image through the typed file calls.
struct DiskFile {
    cap: u32,
    ro: bool,
}

impl SeqFile for DiskFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        match sys::file_read_typed(self.cap, buf) {
            n if n >= 0 => Ok(n as usize),
            e => Err(IoError::from_errno(e)),
        }
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, IoError> {
        match sys::file_write_typed(self.cap, data) {
            n if n >= 0 => Ok(n as usize),
            e => Err(IoError::from_errno(e)),
        }
    }

    fn rewind(&mut self) -> Result<(), IoError> {
        let _ = sys::close_typed(self.cap);
        match sys::open_root(DISK, if self.ro { O_RDONLY } else { O_RDWR }) {
            h if h > 0 => {
                self.cap = h as u32;
                Ok(())
            }
            e => Err(IoError::from_errno(e)),
        }
    }

    fn sync(&mut self) -> Result<(), IoError> {
        if self.ro {
            return Ok(());
        }
        match sys::fsync_typed(self.cap) {
            0 => Ok(()),
            e => Err(IoError::from_errno(e)),
        }
    }
}

/// Open the disk read-write, else read-only; `None` when there is no image.
fn open_disk() -> Option<SeqStore<DiskFile>> {
    let mut st = [0u8; azos_abi::syscall_nr::STAT_BYTES];
    if sys::stat(DISK, &mut st) != 0 {
        return None;
    }
    let bytes = u64::from_le_bytes([st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]]);
    let (cap, ro) = match sys::open_root(DISK, O_RDWR) {
        h if h > 0 => (h as u32, false),
        _ => match sys::open_root(DISK, O_RDONLY) {
            h if h > 0 => (h as u32, true),
            _ => return None,
        },
    };
    Some(SeqStore::new(DiskFile { cap, ro }, bytes, ro))
}

impl ctl::Holder for VcpuClient<Ep> {
    fn state(&mut self) -> Option<u64> {
        sys::dev::value(VcpuCall::state(self)).ok()
    }

    fn pause(&mut self) -> Result<(), u32> {
        sys::dev::value(VcpuCall::pause(self))
    }

    fn resume(&mut self) -> Result<(), u32> {
        sys::dev::value(VcpuCall::resume(self))
    }
}

impl Cpu for VcpuClient<Ep> {
    fn launch(&mut self, pc: u64, arg: u64) -> Result<(), u32> {
        sys::dev::value(VcpuCall::start(self, pc, arg))
    }

    fn request_stop(&mut self) {
        let _ = VcpuCall::stop(self);
    }

    fn run_state(&mut self) -> Option<u64> {
        sys::dev::value(VcpuCall::state(self)).ok()
    }
}

/// Stop what still runs of the guest and give the VM back (`Vm::destroy`: its
/// RAM, trap page and NIC ring are released, the tables freed). `false` when
/// a vCPU thread did not end in time or the VM refused.
fn teardown(vm: &mut VmClient<Ep>, vcpus: &mut [Option<VcpuClient<Ep>>], count: usize, port: u32) -> bool {
    let mut event = [0u8; sys::PORT_EVENT_BYTES];
    // The wait is the port's: the only sleep this program has. A trap posted
    // meanwhile wakes it early, so it goes on to the end of its slice.
    let mut pause = || {
        let until = sys::vdso_now_ns() + STOP_SLICE_MS * 1_000_000;
        while sys::vdso_now_ns() < until {
            let _ = sys::port_wait_until_typed(port, &mut event, until);
        }
    };
    life::halt(vcpus, count, STOP_SLICES, &mut pause) && sys::dev::succeeded(vm.destroy())
}

/// The memory objects this task made for the guest that exists, to give back
/// with it (`sys::shm_release_typed`: the mapping and the capability).
struct Held {
    caps: [u32; HELD_MAX],
    n: usize,
}

static HELD: Single<Held> = Single::new(Held { caps: [0; HELD_MAX], n: 0 });

/// Create a region of `bytes`, map it and say its capability and address:
/// the capability is what the kernel is handed, the address what this task
/// reads and writes. Not recorded: the caller gives it back.
fn make_region(bytes: usize) -> Option<(u32, *mut u8)> {
    let cap = sys::shm_create_typed(bytes.div_ceil(sys::PAGE_SIZE) as u64, sys::SHM_RW);
    if cap <= 0 {
        return None;
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        let _ = sys::shm_release_typed(cap as u32);
        return None;
    }
    Some((cap as u32, va as usize as *mut u8))
}

/// [`make_region`], held for the guest that exists: [`release_held`] gives it
/// back.
fn region(held: &mut Held, bytes: usize) -> Option<(u32, *mut u8)> {
    if held.n == HELD_MAX {
        return None;
    }
    let (cap, va) = make_region(bytes)?;
    held.caps[held.n] = cap;
    held.n += 1;
    Some((cap, va))
}

/// Give back every region held for the guest.
fn release_held(held: &mut Held) {
    for cap in &held.caps[..held.n] {
        let _ = sys::shm_release_typed(*cap);
    }
    held.n = 0;
}

/// Make the guest's RAM, a memory object at a time, and attach it: mapped
/// here for the models, mapped into the guest by the kernel. Stops at the
/// first object that cannot be made or attached (the quota of this task's
/// Domain, the capability table, the VM's refusal): the RAM is then partial
/// and the models see none of it.
fn attach_ram(vm: &mut VmClient<Ep>, ram: &mut SegRam, held: &mut Held, base: u64, bytes: u64) {
    let chunk = (CHUNK_PAGES * sys::PAGE_SIZE) as u64;
    // SAFETY: each pointer `make` answers is a mapping of `len` bytes this task
    // owns and uses for nothing else; the region stays mapped until the guest
    // is given back, and `ram` is reset before that (`Monitor::undo`).
    let r = unsafe {
        guest::attach_all(ram, base, bytes, chunk, |gpa, len| {
            let Some((cap, va)) = region(held, len as usize) else {
                log(b"[vmmd] guest RAM: no memory object (this task's frame budget?)\n");
                return None;
            };
            if !sys::dev::succeeded(vm.ram(Cap::from_raw(cap), gpa)) {
                log(b"[vmmd] guest RAM: the VM refused a range\n");
                return None;
            }
            Some(va)
        })
    };
    if r.is_err() {
        log(b"[vmmd] guest RAM is partial: no device can work\n");
    }
}

/// A file of the volume read front to back, as the kernel loader's source.
struct FileSource(u32);

impl loader::Source for FileSource {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        match sys::file_read_typed(self.0, buf) {
            n if n >= 0 => Ok(n as usize),
            _ => Err(()),
        }
    }
}

/// The kernel's command line, if the volume has one: its first line, up to
/// [`CMDLINE_MAX`] bytes. How many bytes of `buf` it fills.
fn read_cmdline(buf: &mut [u8; CMDLINE_MAX]) -> usize {
    let cap = match sys::open_root(CMDLINE, O_RDONLY) {
        h if h > 0 => h as u32,
        _ => return 0,
    };
    let n = match sys::file_read_typed(cap, buf) {
        n if n > 0 => n as usize,
        _ => 0,
    };
    let _ = sys::close_typed(cap);
    buf[..n].iter().position(|&c| c == b'\n' || c == b'\r' || c == 0).unwrap_or(n)
}

fn log(msg: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, msg);
}

/// A ring the guest's console stopped writing: tell its holder (the ring is
/// closed, for the holder to drain and end) and the operator what did not fit.
/// The ring's region is still mapped here; the caller releases it after.
fn retire(r: Retired) {
    vmctl::ConsoleRing::close(r.ring.base);
    if r.lost == 0 {
        return;
    }
    let mut digits = [0u8; 20];
    let (mut n, mut i) = (r.lost, digits.len());
    while n > 0 {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    log(b"[vmmd] the console ring's holder did not drain it: ");
    log(&digits[i..]);
    log(b" bytes of guest output dropped\n");
}

// ---------------------------------------------------------------------------
// The guest
// ---------------------------------------------------------------------------

/// The device models of a guest: the disk, the NIC, the console whose bytes
/// go to the operator's console or a tool's ring.
type Devices = Machine<SeqStore<DiskFile>, RingLink, Guarded<Sink<Out>>>;

/// What the loop keeps of the guest that exists.
struct Guest {
    machine: Devices,
    rings: Option<Rings>,
    /// The vCPUs the guest is told of (at most the row's).
    cpus: usize,
    /// Bit `k` for vCPU `k` once it was started.
    started: u64,
    /// Where the boot CPU starts, once the kernel is loaded.
    entry: Option<Entry>,
    /// The region of the console ring a tool holds, if one does.
    console: Option<u32>,
}

/// The guest's RAM as the models see it, and the guest itself (`None`: the
/// row is free). In the image, not on the task's small stack; `main` takes the
/// one reference to each and lends it to the [`Monitor`].
static RAM: Single<SegRam> = Single::new(SegRam::new());
static GUEST: Single<Option<Guest>> = Single::new(None);

/// The loop and the service thread meet here.
static MAILBOX: Mailbox = Mailbox::new();
/// The event port, for the service thread to wake the loop.
static PORT: AtomicU32 = AtomicU32::new(0);

/// How the service thread sleeps and wakes the loop.
struct Doorbell;

impl Wake for Doorbell {
    fn wake_monitor(&self) {
        // An event that is due now: the loop's wait on the trap port returns.
        let _ = sys::port_bind_timer(PORT.load(Ordering::Acquire), sys::vdso_now_ns(), CTL_KEY);
    }

    fn park(&self, word: &AtomicU32, seen: u32) {
        let _ = sys::futex_wait(word, seen, 1_000_000_000);
    }

    fn unpark(&self, word: &AtomicU32) {
        let _ = sys::futex_wake(word, 1);
    }
}

/// The stack of the service thread.
#[repr(C, align(16))]
struct CtlStack([u8; CTL_STACK_BYTES]);

static CTL_STACK: Single<CtlStack> = Single::new(CtlStack([0; CTL_STACK_BYTES]));

/// The service thread: accept a call on `endpoint.vmctl`, hand it to the
/// loop, reply with what the loop answered.
extern "C" fn service(_: u64, _: u64, _: u64) -> ! {
    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake, or this row serves no
            // `endpoint.vmctl`): wait a little rather than spin.
            sys::sleep(10);
            continue;
        }
        let rep = MAILBOX.call(&Doorbell, &req);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

/// The monitor's loop as the control plane's host: every act on the real
/// machine, none of the decisions (`ctl`).
struct Monitor<'a> {
    vm: VmClient<Ep>,
    vcpus: [Option<VcpuClient<Ep>>; VCPUS],
    port: u32,
    /// The row's vCPUs: the endpoints to stop and watch.
    row_cpus: usize,
    devices: usize,
    kinds: [Option<Kind>; model::MAX_DEVICES],
    /// Where the row's RAM starts, and how many MiB it has.
    ram_base: u64,
    row_mem_mib: u64,
    /// The kernel `open` found, until `load` reads it.
    image: Option<FileSource>,
    /// What the guest being built sees: CPUs and MiB.
    cpus: usize,
    mem_mib: u64,
    /// The guest's RAM as the models see it, the guest, the regions held for
    /// it and the room the kernel is read through: the loop's alone.
    ram: &'a mut SegRam,
    guest: &'a mut Option<Guest>,
    held: &'a mut Held,
    scratch: &'a mut [u8; life::SCRATCH_BYTES],
}

impl Monitor<'_> {
    fn guest(&mut self) -> Option<&mut Guest> {
        self.guest.as_mut()
    }

    fn close_image(&mut self) {
        if let Some(k) = self.image.take() {
            let _ = sys::close_typed(k.0);
        }
    }

    /// Give back whatever a half-built guest holds: the VM, then the regions.
    fn undo(&mut self) {
        *self.guest = None;
        *self.ram = SegRam::new();
        self.close_image();
        let _ = teardown(&mut self.vm, &mut self.vcpus, self.row_cpus, self.port);
        release_held(self.held);
    }
}

impl Host for Monitor<'_> {
    fn open(&mut self, image: &[u8]) -> Result<(), Fail> {
        // `ctl::image_ok` has accepted the name: a plain relative path.
        let mut path = [0u8; GUEST_DIR.len() + vmctl::IMAGE_MAX + 1];
        path[..GUEST_DIR.len()].copy_from_slice(GUEST_DIR);
        path[GUEST_DIR.len()..GUEST_DIR.len() + image.len()].copy_from_slice(image);
        match sys::open_root(&path[..GUEST_DIR.len() + image.len() + 1], O_RDONLY) {
            h if h > 0 => {
                self.image = Some(FileSource(h as u32));
                Ok(())
            }
            e => Err(Fail::new(cause::IMAGE_OPEN, e as u64)),
        }
    }

    fn build(&mut self, cpus: u32, mem_mib: u32) -> Result<(), Fail> {
        self.cpus = cpus as usize;
        self.mem_mib = mem_mib as u64;
        fn fail(m: &mut Monitor<'_>, step: u64) -> Result<(), Fail> {
            m.undo();
            Err(Fail::new(cause::BUILD, step))
        }
        if !sys::dev::succeeded(self.vm.create()) {
            log(b"[vmmd] vm.0 could not be created\n");
            self.close_image();
            return Err(Fail::new(cause::BUILD, 1));
        }
        *self.ram = SegRam::new();
        attach_ram(&mut self.vm, self.ram, self.held, self.ram_base, self.row_mem_mib << 20);
        if !self.ram.complete() {
            return fail(self, 2);
        }
        // The trap page, which `port` says has an entry.
        let rings = match region(self.held, trap::PAGE_BYTES) {
            // SAFETY: the page is `PAGE_BYTES` long, page-aligned and ours until
            // the guest is given back.
            Some((cap, page)) if sys::dev::succeeded(self.vm.traps(Cap::from_raw(cap), Cap::from_raw(self.port), EVENT_KEY)) => {
                unsafe { Rings::new(page) }
            }
            _ => {
                log(b"[vmmd] the trap page could not be attached: no guest access can be served\n");
                return fail(self, 3);
            }
        };
        // The guest NIC is the vmmd end of a ring pair in a region of its own;
        // attaching it is the guest's way to the network, which its envelope may
        // not allow.
        let wants_net = self.kinds.contains(&Some(Kind::Net));
        let link = wants_net
            .then(|| region(self.held, ringlink::REGION_BYTES))
            .flatten()
            .filter(|(cap, _)| {
                let ok = sys::dev::succeeded(self.vm.net(Cap::from_raw(*cap)));
                if !ok {
                    log(b"[vmmd] the VM's envelope allows no network: the guest has no NIC\n");
                }
                ok
            })
            // SAFETY: the region is `REGION_BYTES` long, page-aligned and ours until
            // the guest is given back.
            .map(|(_, p)| unsafe { RingLink::new(p) });
        let net = link.map(|l| Net::new(l, MAC));
        let blk = open_disk().map(Blk::new);
        let machine = Machine::new(self.kinds, Some(Console::new(Guarded::new(Sink::new(Out)))), blk, net);
        for (base, len, dev) in machine.windows() {
            if !sys::dev::succeeded(self.vm.window(sys::dev::vm::SPACE_MMIO, base, len, dev as u32)) {
                log(b"[vmmd] a device window was refused\n");
            }
        }
        *self.guest = Some(Guest { machine, rings: Some(rings), cpus: self.cpus, started: 0, entry: None, console: None });
        Ok(())
    }

    fn load(&mut self) -> Result<(), Fail> {
        let Some(mut kernel) = self.image.take() else { return Err(Fail::new(cause::IMAGE_OPEN, 0)) };
        let mut args = [0u8; CMDLINE_MAX];
        let nargs = read_cmdline(&mut args);
        let setup = Setup {
            isa: loader::HOST,
            cpus: self.cpus,
            timebase_hz: sys::vdso_timebase_hz().min(u32::MAX as u64) as u32,
            devices: &self.kinds[..self.devices.min(model::MAX_DEVICES)],
            args: &args[..nargs],
        };
        let mut view = Limited::new(&mut *self.ram, self.mem_mib << 20);
        let prepared = life::prepare(&mut kernel, &mut view, &setup, &mut *self.scratch);
        let _ = sys::close_typed(kernel.0);
        match prepared {
            Ok(entry) => {
                if let Some(g) = self.guest() {
                    g.entry = Some(entry);
                }
                Ok(())
            }
            Err(e) => {
                log(b"[vmmd] guest kernel refused: ");
                log(e.reason());
                log(b"\n");
                Err(Fail::new(cause::IMAGE_REFUSED, ctl::refusal_code(&e)))
            }
        }
    }

    fn boot(&mut self) -> Result<(), Fail> {
        let Some((cpus, entry)) = self.guest().and_then(|g| g.entry.map(|e| (g.cpus, e))) else {
            return Err(Fail::new(cause::NOT_CREATED, 0));
        };
        match life::boot(&mut self.vcpus, cpus, entry) {
            Boot::Started => {
                if let Some(g) = self.guest() {
                    g.started = 1;
                }
                log(b"[vmmd] guest kernel loaded; vCPU 0 started\n");
                Ok(())
            }
            Boot::TooMany => {
                log(b"[vmmd] guest kernel loaded; more vCPUs than this monitor serves: not started\n");
                Err(Fail::new(cause::START_REFUSED, u64::MAX))
            }
            Boot::NoEndpoint(k) => {
                log(b"[vmmd] guest kernel loaded; the row grants no endpoint for one of its vCPUs: not started\n");
                Err(Fail::new(cause::START_REFUSED, k as u64))
            }
            Boot::Refused(code) => {
                log(b"[vmmd] guest kernel loaded; vCPU 0 was not started (no guest entry on this ISA, or refused)\n");
                Err(Fail::new(cause::START_REFUSED, code as u64))
            }
        }
    }

    fn pause(&mut self) -> Result<(), Fail> {
        ctl::pause_all(&mut self.vcpus, self.row_cpus)
    }

    fn resume(&mut self) -> Result<(), Fail> {
        ctl::resume_all(&mut self.vcpus, self.row_cpus)
    }

    fn paused(&mut self) -> bool {
        ctl::all_held(&mut self.vcpus, self.row_cpus)
    }

    fn halt(&mut self) -> bool {
        self.close_image();
        // The ring goes first, and the guest's output back to the operator's
        // console: the guest may outlive a failed give-back, and must not
        // write a region that is no longer mapped.
        if let Some(g) = self.guest() {
            if let Some(r) = g.machine.console.as_mut().and_then(|t| t.dev.term.inner.detach()) {
                retire(r);
            }
            if let Some(c) = g.console.take() {
                let _ = sys::shm_release_typed(c);
            }
        }
        let freed = teardown(&mut self.vm, &mut self.vcpus, self.row_cpus, self.port);
        if freed {
            *self.guest = None;
            *self.ram = SegRam::new();
            release_held(self.held);
        }
        freed
    }

    fn console(&mut self) -> Result<u32, Fail> {
        let Some((cap, va)) = make_region(vmctl::CONSOLE_RING_PAGES as usize * sys::PAGE_SIZE) else {
            return Err(Fail::new(cause::NO_CONSOLE, 0));
        };
        let ring = azos_rings::region::SpscStream { base: va as usize, cap: vmctl::CONSOLE_RING_CAP };
        ring.init();
        let Some(g) = self.guest() else {
            let _ = sys::shm_release_typed(cap);
            return Err(Fail::new(cause::NOT_CREATED, 0));
        };
        if let Some(old) = g.machine.console.as_mut().and_then(|t| t.dev.term.inner.attach(ring)) {
            retire(old);
        }
        // The ring the last tool held is closed and not written any more:
        // give it back.
        if let Some(old) = g.console.replace(cap) {
            let _ = sys::shm_release_typed(old);
        }
        Ok(cap)
    }

    fn log(&mut self, line: &[u8]) {
        log(line);
    }
}

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    log(b"[vmmd] AzOS virtual-machine monitor (device models for vm.0)\n");
    let Some(vm_ep) = sys::dev::lookup(sys::dev::key::VM, sys::dev::vm::vm_badge(0)) else {
        log(b"[vmmd] no vm.0 endpoint in this row: nothing to serve\n");
        sys::exit(0);
    };
    let mut vm = VmClient::new(Ep(vm_ep));

    // No `[guest.NAME]` row: the endpoint is granted, nothing stands behind it.
    let state = sys::dev::value(vm.state());
    if state == Err(sys::dev::outcome::NO_RESOURCE) {
        log(b"[vmmd] no guest is declared: nothing to serve\n");
        sys::exit(0);
    }
    // [cpus, mem_mib, envelope | devices << 8 | vmid << 16, backends, ram_base]
    let Ok(cfg) = sys::dev::value(vm.config()) else {
        log(b"[vmmd] vm.0 has no configuration\n");
        sys::exit(1);
    };
    let (cpus, devices) = (cfg[0] as usize, ((cfg[2] >> 8) & 0xFF) as usize);
    let kinds = model::kinds_of(cfg[3], devices);

    // The vCPUs this program starts, stops, wakes and interrupts: one endpoint
    // each, which the row grants (`vcpu.0.k`, k below the guest's CPUs).
    let mut vcpus: [Option<VcpuClient<Ep>>; VCPUS] = [const { None }; VCPUS];
    for (k, slot) in vcpus.iter_mut().enumerate().take(cpus) {
        *slot = sys::dev::lookup(sys::dev::key::VCPU, sys::dev::vm::vcpu_badge(0, k as u32))
            .map(|h| VcpuClient::new(Ep(h)));
    }

    // The port that says a trap page has an entry, and that a call is waiting.
    // Without it there is nothing to sleep on and nothing the kernel can wake:
    // no point in serving a guest.
    let port = sys::port_create_typed();
    if port <= 0 {
        log(b"[vmmd] no event port: the kernel cannot tell this monitor of a guest access\n");
        sys::exit(1);
    }
    PORT.store(port as u32, Ordering::Release);

    // A VM that is already created was left so by a monitor that ended: its
    // vCPUs end on their own once its port is gone, and what it holds is
    // given back before this one makes its own.
    if state == Ok(1) {
        log(b"[vmmd] vm.0 was left created by an earlier monitor: giving it back\n");
        if !teardown(&mut vm, &mut vcpus, cpus, port as u32) {
            log(b"[vmmd] vm.0 could not be given back\n");
            sys::exit(1);
        }
    }

    // The loop's state, which no other thread touches: the one reference to
    // each, lent to the monitor.
    // SAFETY: this is the loop's thread, and these are the only references
    // ever made to the four statics.
    let (ram, guest, held, scratch) = unsafe { (RAM.get(), GUEST.get(), HELD.get(), SCRATCH.get()) };
    let mut mon = Monitor {
        vm,
        vcpus,
        port: port as u32,
        row_cpus: cpus,
        devices,
        kinds,
        ram_base: cfg[4],
        row_mem_mib: cfg[1],
        image: None,
        cpus,
        mem_mib: cfg[1],
        ram,
        guest,
        held,
        scratch,
    };
    let mut ctl = Control::new(Row { cpus: cpus as u32, mem_mib: cfg[1].min(u32::MAX as u64) as u32 });

    // The control plane: the service thread takes the calls of `endpoint.vmctl`.
    // SAFETY: the stack is the service thread's alone, its top is 16-aligned.
    let top = unsafe { CTL_STACK.get() as *mut CtlStack as usize + core::mem::size_of::<CtlStack>() };
    if sys::thread_create(service, top, 0, core::ptr::null_mut()) < 0 {
        log(b"[vmmd] no thread for the control plane: VmCtl is not served\n");
    }

    // The kernel the volume carries starts through the calls a tool makes.
    if ctl.autostart(&mut mon) {
        log(b"[vmmd] autostart: the volume's guest runs\n");
    }

    log(b"[vmmd] serving\n");
    let mut event = [0u8; sys::PORT_EVENT_BYTES];
    let mut next_watch = sys::vdso_now_ns() + WATCH_MS * 1_000_000;
    loop {
        // A call waiting: run it between two passes, answer on the mailbox.
        if let Some(req) = MAILBOX.take() {
            let mut rep = MsgDesc::default();
            let mut bound = ctl::Bound { ctl: &mut ctl, host: &mut mon, ring_rights: CONSOLE_RIGHTS };
            let _ = VmCtlIdl::dispatch(&mut bound, &req, &mut rep);
            MAILBOX.answer(&Doorbell, &rep);
        }
        // A pause asked becomes taken once every vCPU holds the guest.
        ctl.settle(&mut mon);

        let mut ms = IDLE_MS;
        let Monitor { ram, guest, vcpus, .. } = &mut mon;
        if let Some(g) = guest.as_mut() {
            g.machine.tick(sys::vdso_now_ns());
            let served = match g.rings.as_mut() {
                Some(r) => g.machine.serve(r, &mut **ram),
                None => model::Served { raised: g.machine.poll(&mut **ram), answered: 0 },
            };
            // The vCPUs that were answered are waiting for it: wake them.
            for k in 0..g.cpus.min(VCPUS) {
                if served.answered & (1 << k) != 0 {
                    if let Some(c) = vcpus[k].as_mut() {
                        let _ = c.kick();
                    }
                }
            }
            for i in 0..devices.min(model::MAX_DEVICES) {
                if served.raised & (1 << i) != 0 {
                    if let Some(c) = vcpus[0].as_mut() {
                        let _ = c.inject(model::irq_line(i));
                    }
                }
            }
            // A request parked for want of budget goes on soon; otherwise sleep
            // on the port until a trap is posted or the next look at the devices.
            ms = if g.machine.busy() {
                BUSY_MS
            } else if ram.range().1 == 0 {
                IDLE_MS
            } else {
                POLL_MS
            };
            // One vCPU leaving ends the guest (see `life`): stop the others and
            // give the VM back. The row is free again.
            if g.started != 0 && sys::vdso_now_ns() >= next_watch {
                next_watch = sys::vdso_now_ns() + WATCH_MS * 1_000_000;
                if let Watch::Over { fault } = life::watch(&mut vcpus[..], g.cpus, g.started) {
                    log(if fault.is_some() {
                        b"[vmmd] a vCPU ended on an exit nothing serves: the guest is over\n"
                    } else {
                        b"[vmmd] a vCPU stopped: the guest is over\n"
                    });
                    let freed = mon.halt();
                    log(if freed { b"[vmmd] vm.0 given back\n" } else { b"[vmmd] vm.0 could not be given back\n" });
                    if !freed {
                        sys::exit(1);
                    }
                    ctl.finished(fault.is_some());
                    continue;
                }
            }
        }
        let _ = sys::port_wait_until_typed(port as u32, &mut event, sys::vdso_now_ns() + ms * 1_000_000);
    }
}

/// The rights the console ring is lent with: read and write (the holder moves
/// the ring's tail) and map.
const CONSOLE_RIGHTS: u16 = (azos_abi::cap::CapPerms::RW.bits() | azos_abi::cap::CapPerms::MAP.bits()) as u16;
