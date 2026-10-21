// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The micro kernel: the static task table built from the signed topology,
//! the syscall surface, and the switch.
//!
//! One hart, no preemption inside the kernel: a trap runs to completion on
//! the one kernel stack and a task that cannot continue (a call waiting for
//! its reply, a server waiting for a request, a sleeper) is a saved
//! [`Frame`] with its state set, never a kernel stack held. Every handler
//! therefore either writes its result into the caller's frame at once or
//! leaves the frame for whoever completes the exchange.
//!
//! Hardware is behind [`Hw`], so the whole of this file runs on the host
//! under the test suite (`tests/host/micro-tests`) with a fake: the same
//! decisions the QEMU image takes.
//!
//! The syscall surface is a subset of the main kernel's, at the same
//! numbers, registers and result codes (`azos_abi`): exit, getpid, yield,
//! sleep, uptime, console write, capability lookup and typed close, the
//! four fast-IPC calls over named endpoints, and `SYS_SPAWN_EX` for a row
//! the caller holds a launch capability for. There is no fork and no exec:
//! a task exists because the topology declares a row for it. Any other
//! number answers -1, as in the main kernel.

use core::fmt::Write;

use azos_abi::cap::{ty, CapHandle, CapKind, CapPerms, CapType};
use azos_abi::error::Errno;
use azos_abi::invoke::{is_domain_self, op_of, DOMAIN_UPTIME, LOG_CONSOLE_WRITE, INVOKE_FLAGS_KNOWN, INVOKE_OP_MASK, INVOKE_REGS};
use azos_abi::syscall_nr::*;
use azos_topology::types::{CapSpec, TaskSpec};
use azos_topology::{RowSched, Topology};

use crate::captable::{CapError, CapSlot, CapTable};
use crate::ceiling;
use crate::chip;
use crate::config::*;
use crate::domain::{contig_size, round_up, Domain, DomainError, Kind, Pool, Region};
use crate::grant::Grants;
use crate::pi_attr::PiAttr;
use crate::pmp_core::{self, PmpEntry, R, W, X};
use crate::rt_core::{us_to_ticks, Cbs};
use crate::sc::{classify, Class};
use crate::sched::{self, Entity};

/// The registers of a trapped task: x0 is unused (zero), then the program
/// counter. `trap.rs` saves into and restores from this layout.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Frame {
    /// x0..x31 (x0's slot is never read).
    pub x: [usize; 32],
    /// The `mepc` to resume at.
    pub pc: usize,
}

const _: () = assert!(core::mem::offset_of!(Frame, pc) == 32 * core::mem::size_of::<usize>());

impl Frame {
    /// All zero.
    pub const ZERO: Self = Self { x: [0; 32], pc: 0 };
}

/// The a-registers are x10..x17.
const A0: usize = 10;
const A7: usize = 17;
const SP: usize = 2;
const GP: usize = 3;

/// One region of a task's domain as the task is told of it: an address and
/// a length are one machine word each (the block is read by the task that is
/// told, on the same machine), the rest are bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct RegionRec {
    /// First byte.
    pub base: usize,
    /// Length in bytes.
    pub size: usize,
    /// `pmp_core::{R, W, X}` bits.
    pub perm: u8,
    /// [`REGION_ANON`], [`REGION_PHYS`] or [`REGION_CONTIG`].
    pub kind: u8,
    /// For a Phys region the `mmio.N` index, for a Contig one the pipeline's
    /// index in the topology; 0 for Anon.
    pub index: u8,
    /// 0.
    pub _pad: u8,
}

/// [`RegionRec::kind`]: the task's own memory.
pub const REGION_ANON: u8 = 0;
/// [`RegionRec::kind`]: a device window.
pub const REGION_PHYS: u8 = 1;
/// [`RegionRec::kind`]: a contiguous block.
pub const REGION_CONTIG: u8 = 2;

/// Regions a start block lists: the task's own part and what its
/// capabilities map. Eight regions at one PMP entry each fill a domain.
pub const START_REGIONS: usize = 8;

/// The block the kernel writes at the top of a task's own memory and points
/// its second argument register at (the micro kernel's startup block, in the
/// place of `mmap` and `DOMAIN_MMIO_MAP`: with no MMU nothing is mapped, so a
/// task is told where the memory it was granted is). The stack starts below
/// it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct StartInfo {
    /// Regions listed, `1..=START_REGIONS`; the first is always the Anon one.
    pub n: u32,
    /// 0.
    pub _pad: u32,
    /// The regions.
    pub regions: [RegionRec; START_REGIONS],
}

// Two words and four bytes, padded to a word: 12 bytes on rv32.
const REGION_REC: usize = (2 * core::mem::size_of::<usize>() + 4).next_multiple_of(core::mem::size_of::<usize>());
const _: () = assert!(core::mem::size_of::<RegionRec>() == REGION_REC);
const _: () = assert!(core::mem::size_of::<StartInfo>() == 8 + START_REGIONS * REGION_REC);

/// What the kernel needs from the machine.
pub trait Hw {
    /// `mtime`, in timebase ticks.
    fn now(&self) -> u64;
    /// Write bytes to the console.
    fn console(&mut self, bytes: &[u8]);
    /// Load the whole PMP table (`PMP_ENTRIES` entries).
    fn program_pmp(&mut self, table: &[PmpEntry; PMP_ENTRIES]);
    /// Copy `out.len()` bytes from the address `addr`. The kernel calls this
    /// only for a range a task's domain admitted.
    fn read_user(&self, addr: usize, out: &mut [u8]);
}

struct Out<'a, H: Hw>(&'a mut H);

impl<H: Hw> Write for Out<'_, H> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.console(s.as_bytes());
        Ok(())
    }
}

macro_rules! say {
    ($hw:expr, $($arg:tt)*) => {{ let _ = writeln!(Out(&mut *$hw), $($arg)*); }};
}

/// An image the kernel can start: the name a topology row carries and the
/// task's entry point.
#[derive(Clone, Copy)]
pub struct Image {
    /// `NAME.ELF`, as the row spells it.
    pub name: &'static str,
    /// The entry function: its arguments are the base of the task's own
    /// region and the address of its [`StartInfo`].
    pub entry: extern "C" fn(usize, usize) -> !,
}

/// Where the linker put the regions.
#[derive(Clone, Copy)]
pub struct BootInfo {
    /// Kernel text and read-only data: readable and executable by tasks.
    pub code: (usize, usize),
    /// The pool the Anon regions are carved from.
    pub pool: (usize, usize),
    /// The pool the contiguous regions are carved from.
    pub contig: (usize, usize),
    /// The global pointer the image was linked for: the code a task runs is
    /// compiled against it, so a task starts with it.
    pub gp: usize,
}

/// Why the topology cannot be run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BootError {
    /// A row names no image in this build.
    UnknownImage(usize),
    /// More task slots (rows times instances) than `MICRO_MAX_TASKS`.
    TooManyTasks,
    /// A row declares no memory (`mem_pages`).
    NoMemBudget(usize),
    /// The pool cannot hold every row's region.
    PoolExhausted,
    /// The contiguous pool cannot hold every pipeline.
    ContigExhausted,
    /// A row holds more caps than `MICRO_CAPS_PER_TASK`.
    TooManyCaps(usize),
    /// The row's memory is too small for its stack and grants.
    NoRoomForGrants(usize),
    /// A capability of a kind this kernel does not mint.
    UnsupportedCap(usize),
    /// A capability target that names nothing here.
    BadTarget(usize),
    /// A row's domain does not fit the PMP entries one task is given.
    Domain(usize, DomainError),
    /// More named endpoints than `MICRO_MAX_ENDPOINTS`.
    TooManyEndpoints,
    /// Two rows ask to serve one endpoint.
    TwoServers(usize),
    /// An endpoint whose server is in the idle class while a client is not:
    /// the server would wait behind every runnable real-time task, and no
    /// ceiling can run a task that is never picked to reach its accept.
    ServerBelowClient(usize),
    /// A deadline row the CBS arithmetic cannot take.
    BadProfile(usize),
    /// No started idle-class row without an endpoint capability: with nothing
    /// runnable the hart would have nothing to run (see [`Kernel`]'s floor).
    NoIdle,
    /// A capability that could not be installed (full table).
    NoCapSlot(usize),
    /// A capability with an op mask (`CapSpec::ops`): the mask restricts the ops
    /// of a kernel-hosted interface, and this kernel hosts none, so the row
    /// would run with a wider reach than it declares and is refused instead.
    OpMask(usize),
    /// The kernel's code window is not a multiple of the PMP granularity
    /// (the linker script aligns it; an image linked another way is refused
    /// here, not at the first switch).
    CodeWindow,
}

/// The state of one task slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Reserved and not started: `SYS_SPAWN_EX` may start it.
    Unborn,
    /// Runnable (or running).
    Ready,
    /// Waiting for `wake_at`.
    Sleeping,
    /// Waiting for the reply to a call on `ep`. `accepted`: a server took it.
    Calling { ep: u8, gen: u16, accepted: bool },
    /// A server waiting for a request.
    Accepting,
    /// Ended (a fault or `SYS_EXIT`); `SYS_SPAWN_EX` may start it again.
    Dead,
}

/// One task slot.
pub struct Task {
    state: State,
    frame: Frame,
    domain: Domain,
    info: StartInfo,
    grants: Grants,
    caps_at: usize,
    row: usize,
    image: usize,
    wake_at: u64,
    call_gen: u16,
    exit_code: isize,
}

impl Task {
    const EMPTY: Self = Self {
        state: State::Unborn,
        frame: Frame::ZERO,
        domain: Domain::new(TASK_PMP_ENTRIES, GRAIN_LOG2),
        info: StartInfo { n: 0, _pad: 0, regions: [RegionRec { base: 0, size: 0, perm: 0, kind: 0, index: 0, _pad: 0 }; START_REGIONS] },
        grants: Grants::EMPTY,
        caps_at: 0,
        row: 0,
        image: 0,
        wake_at: 0,
        call_gen: 0,
        exit_code: 0,
    };
}

/// The request queue of an endpoint, in the grant of the task that serves
/// it: a ring of client slot indices.
#[repr(C)]
struct EpQueue {
    head: u8,
    len: u8,
    slots: [u8; MAX_TASKS],
}

impl EpQueue {
    fn push(&mut self, c: usize) -> bool {
        if self.len as usize >= MAX_TASKS {
            return false;
        }
        self.slots[(self.head as usize + self.len as usize) % MAX_TASKS] = c as u8;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let c = self.slots[self.head as usize];
        self.head = ((self.head as usize + 1) % MAX_TASKS) as u8;
        self.len -= 1;
        Some(c as usize)
    }

    fn remove(&mut self, c: usize) {
        let n = self.len as usize;
        let mut kept = 0;
        for k in 0..n {
            let v = self.slots[(self.head as usize + k) % MAX_TASKS];
            if v as usize != c {
                self.slots[(self.head as usize + kept) % MAX_TASKS] = v;
                kept += 1;
            }
        }
        self.len = kept as u8;
    }
}

/// A named endpoint.
#[derive(Clone, Copy)]
struct Endpoint<'t> {
    name: &'t [u8],
    /// The slot that serves it (the first instance of the row holding `READ`).
    server: Option<u8>,
    /// The server's request queue, in its grant.
    queue_at: usize,
    ceiling: PiAttr,
    /// The server closed its `READ` capability: nothing serves the endpoint
    /// (calls are refused, accept finds no request) until its row starts
    /// again and is given the capability anew.
    revoked: bool,
}

/// A `[pipeline.NAME]` contiguous region.
#[derive(Clone, Copy)]
struct Pipe<'t> {
    name: &'t [u8],
    region: Region,
}

/// What a capability target names here.
enum Target {
    Endpoint(usize),
    Mmio(usize),
    Pipe(usize),
    Launch(usize),
}

/// The kernel.
pub struct Kernel<'t> {
    topo: Option<&'t Topology<'t>>,
    images: &'t [Image],
    info: BootInfo,
    tasks: [Task; MAX_TASKS],
    ents: [Entity; MAX_TASKS],
    n_tasks: usize,
    eps: [Endpoint<'t>; MAX_ENDPOINTS],
    n_eps: usize,
    pipes: [Pipe<'t>; azos_topology::types::MAX_PIPELINES],
    n_pipes: usize,
    cur: usize,
    seq: u64,
    last_acct: u64,
    /// The idle-class task that always runs when nothing else can: started at
    /// boot, holding no endpoint capability, so it can neither call nor
    /// accept. It never blocks (`SYS_SLEEP_UNTIL` returns at once) and never ends
    /// (an exit or a fault restarts it), so the scheduler always has a task.
    floor: usize,
}

fn zero(base: usize, len: usize) {
    // SAFETY: the kernel zeroes memory it carved from its own pools (the
    // pool and the contiguous pool) at boot, before any task runs.
    unsafe { core::ptr::write_bytes(base as *mut u8, 0, len) };
}

impl<'t> Kernel<'t> {
    /// An empty kernel, `const` so it can live in `.bss`.
    pub const fn new() -> Self {
        Self {
            topo: None,
            images: &[],
            info: BootInfo { code: (0, 0), pool: (0, 0), contig: (0, 0), gp: 0 },
            tasks: [const { Task::EMPTY }; MAX_TASKS],
            ents: [const { Entity::unborn() }; MAX_TASKS],
            n_tasks: 0,
            eps: [const { Endpoint { name: &[], server: None, queue_at: 0, ceiling: PiAttr::Idle, revoked: false } }; MAX_ENDPOINTS],
            n_eps: 0,
            pipes: [const { Pipe { name: &[], region: Region { base: 0, size: 0, perm: 0, kind: Kind::Contig } } };
                azos_topology::types::MAX_PIPELINES],
            n_pipes: 0,
            cur: 0,
            seq: 1,
            last_acct: 0,
            floor: 0,
        }
    }

    fn topo(&self) -> &'t Topology<'t> {
        self.topo.expect("booted")
    }

    // ── boot ────────────────────────────────────────────────────────────

    /// Build the task table from `topo` (already verified and admitted) and
    /// start every row marked `start`. Nothing runs yet.
    pub fn boot<H: Hw>(
        &mut self,
        hw: &mut H,
        topo: &'t Topology<'t>,
        images: &'t [Image],
        info: BootInfo,
    ) -> Result<(), BootError> {
        if info.code.1.checked_sub(info.code.0).and_then(|len| pmp_core::region(info.code.0, len, R | X, GRAIN_LOG2)).is_none() {
            return Err(BootError::CodeWindow);
        }
        self.topo = Some(topo);
        self.images = images;
        self.info = info;
        self.last_acct = hw.now();

        // Contiguous regions first: every task that names a pipeline needs it.
        let mut contig = Pool::new(info.contig.0, info.contig.1);
        for p in topo.pipelines() {
            let size = contig_size(p.dma_pages as usize * 4, GRAIN_LOG2);
            let base = contig.alloc(size, size).ok_or(BootError::ContigExhausted)?;
            zero(base, size);
            self.pipes[self.n_pipes] = Pipe {
                name: p.name.as_bytes(),
                region: Region { base, size, perm: R | W, kind: Kind::Contig },
            };
            self.n_pipes += 1;
        }

        // Endpoints: every `endpoint.NAME` target, one server each. A grant that
        // carries an op mask names an interface this kernel does not host: refused.
        for (r, row) in topo.tasks().iter().enumerate() {
            for c in topo.caps_of(row) {
                if c.ops != 0 {
                    return Err(BootError::OpMask(r));
                }
                if c.kind != CapKind::Endpoint {
                    continue;
                }
                let name = azos_topology::types::endpoint_target(c).ok_or(BootError::BadTarget(r))?;
                self.intern_endpoint(name)?;
            }
        }

        // Task slots: a row's instances, each with its region, grants and
        // domain, reserved now so a topology that does not fit is refused at
        // boot, not at the first spawn.
        let mut pool = Pool::new(info.pool.0, info.pool.1);
        let mut slot = 0;
        for (r, row) in topo.tasks().iter().enumerate() {
            let image = images
                .iter()
                .position(|i| i.name.as_bytes() == row.name.as_bytes())
                .ok_or(BootError::UnknownImage(r))?;
            for inst in 0..row.instance_count() {
                if slot >= MAX_TASKS {
                    return Err(BootError::TooManyTasks);
                }
                self.reserve(slot, r, image, inst == 0, &mut pool)?;
                slot += 1;
            }
        }
        self.n_tasks = slot;

        // Ceilings: the server's attribute raised by every client's.
        for e in 0..self.n_eps {
            let Some(server) = self.eps[e].server else { continue };
            let name = self.eps[e].name;
            let attr = |s: usize| ceiling::base_attr(self.ents[s].sc.class(), self.prio_of(s));
            let clients = (0..self.n_tasks)
                .filter(|&s| self.row_holds(self.tasks[s].row, name, CapPerms::WRITE))
                .map(attr);
            let ceil = ceiling::endpoint_ceiling(attr(server as usize), clients);
            if self.ents[server as usize].sc.class() == Class::Idle && matches!(ceil, PiAttr::Rt { .. }) {
                return Err(BootError::ServerBelowClient(self.tasks[server as usize].row));
            }
            self.eps[e].ceiling = ceil;
        }

        for s in 0..self.n_tasks {
            if topo.tasks()[self.tasks[s].row].start {
                self.start(s)?;
            }
        }
        let floor = (0..self.n_tasks).find(|&s| {
            self.ents[s].runnable
                && self.ents[s].sc.class() == Class::Idle
                && !topo.caps_of(&topo.tasks()[self.tasks[s].row]).iter().any(|c| c.kind == CapKind::Endpoint)
        });
        self.floor = floor.ok_or(BootError::NoIdle)?;
        say!(hw, "[MICRO] {} tasks, {} endpoints, {} pipelines; pool {} B left", self.n_tasks, self.n_eps, self.n_pipes, pool.left());
        Ok(())
    }

    fn prio_of(&self, s: usize) -> u8 {
        self.ents[s].sc.prio_or_weight.load(core::sync::atomic::Ordering::Relaxed).min(255) as u8
    }

    fn intern_endpoint(&mut self, name: &'t [u8]) -> Result<usize, BootError> {
        if let Some(e) = self.eps[..self.n_eps].iter().position(|e| e.name == name) {
            return Ok(e);
        }
        if self.n_eps >= MAX_ENDPOINTS {
            return Err(BootError::TooManyEndpoints);
        }
        self.eps[self.n_eps].name = name;
        self.n_eps += 1;
        Ok(self.n_eps - 1)
    }

    /// Whether row `r` holds a capability with `perm` on the endpoint `name`.
    fn row_holds(&self, r: usize, name: &[u8], perm: CapPerms) -> bool {
        let topo = self.topo();
        topo.caps_of(&topo.tasks()[r]).iter().any(|c| {
            c.kind == CapKind::Endpoint
                && azos_topology::types::endpoint_target(c) == Some(name)
                && c.perms.contains(perm)
        })
    }

    /// What `c` names, or why it names nothing.
    fn target(&self, r: usize, c: &CapSpec<'t>) -> Result<Target, BootError> {
        let t = c.target.as_str();
        match c.kind {
            CapKind::Endpoint => {
                let name = azos_topology::types::endpoint_target(c).ok_or(BootError::BadTarget(r))?;
                self.eps[..self.n_eps].iter().position(|e| e.name == name).map(Target::Endpoint).ok_or(BootError::BadTarget(r))
            }
            CapKind::Device => {
                let i: usize = t.strip_prefix("mmio.").and_then(|s| s.parse().ok()).ok_or(BootError::BadTarget(r))?;
                let region = chip::MMIO.get(i).ok_or(BootError::BadTarget(r))?;
                let want = perm_bits(c.perms);
                if want & !region.perm != 0 {
                    return Err(BootError::BadTarget(r));
                }
                Ok(Target::Mmio(i))
            }
            CapKind::MemObj => {
                let name = t.strip_prefix("pipeline.").ok_or(BootError::BadTarget(r))?;
                self.pipes[..self.n_pipes].iter().position(|p| p.name == name.as_bytes()).map(Target::Pipe).ok_or(BootError::BadTarget(r))
            }
            CapKind::Node => {
                let row = self.topo().tasks().iter().position(|k| k.name.as_str() == t).ok_or(BootError::BadTarget(r))?;
                Ok(Target::Launch(row))
            }
            _ => Err(BootError::UnsupportedCap(r)),
        }
    }

    /// Reserve slot `s` for row `r`: its Anon region from the pool, the
    /// grants carved from the region's top (the capability table, and the
    /// request queue of every endpoint the row serves), the domain, and the
    /// scheduling parameters.
    fn reserve(&mut self, s: usize, r: usize, image: usize, first: bool, pool: &mut Pool) -> Result<(), BootError> {
        let topo = self.topo();
        let row: &TaskSpec<'t> = &topo.tasks()[r];
        let caps = topo.caps_of(row);
        // The row's capabilities and the console every task is started with.
        if caps.len() + 1 > CAPS_PER_TASK {
            return Err(BootError::TooManyCaps(r));
        }
        if row.mem_pages == 0 {
            return Err(BootError::NoMemBudget(r));
        }
        let size = round_up(row.mem_pages as usize * 4096, GRAIN_LOG2);
        // A power-of-two region on its own alignment is one PMP entry.
        let align = if size.is_power_of_two() { size } else { 1 << GRAIN_LOG2 };
        let base = pool.alloc(size, align).ok_or(BootError::PoolExhausted)?;
        zero(base, size);

        // Grants: the capability table, then one queue per endpoint served.
        let serves = |c: &&CapSpec<'t>| c.kind == CapKind::Endpoint && c.perms.contains(CapPerms::READ);
        let n_serves = if first { caps.iter().filter(serves).count() } else { 0 };
        if n_serves > MAX_ENDPOINTS {
            return Err(BootError::TooManyEndpoints);
        }
        let mut items = [(0usize, 1usize); 1 + MAX_ENDPOINTS];
        items[0] = (CAPS_PER_TASK * core::mem::size_of::<CapSlot>(), core::mem::align_of::<CapSlot>());
        for it in items.iter_mut().skip(1).take(n_serves) {
            *it = (core::mem::size_of::<EpQueue>(), core::mem::align_of::<EpQueue>());
        }
        let reserve = Grants::need(&items[..1 + n_serves]);
        let mut grants = Grants::split(base, size, reserve, MIN_STACK + core::mem::size_of::<StartInfo>(), GRAIN_LOG2).ok_or(BootError::NoRoomForGrants(r))?;
        let caps_at = grants.alloc(items[0].0, items[0].1).ok_or(BootError::NoRoomForGrants(r))?;
        for c in caps.iter().filter(serves) {
            if !first {
                break;
            }
            let Target::Endpoint(e) = self.target(r, c)? else { return Err(BootError::BadTarget(r)) };
            if self.eps[e].server.is_some() {
                return Err(BootError::TwoServers(r));
            }
            let q = grants.alloc(core::mem::size_of::<EpQueue>(), core::mem::align_of::<EpQueue>()).ok_or(BootError::NoRoomForGrants(r))?;
            self.eps[e].server = Some(s as u8);
            self.eps[e].queue_at = q;
        }

        // Domain: the task's own part, then what its capabilities map.
        let mut domain = Domain::new(TASK_PMP_ENTRIES, GRAIN_LOG2);
        let (abase, alen) = grants.app();
        let mut info = StartInfo { n: 0, _pad: 0, regions: [RegionRec { base: 0, size: 0, perm: 0, kind: 0, index: 0, _pad: 0 }; START_REGIONS] };
        let mut add = |domain: &mut Domain, reg: Region, index: u8| -> Result<(), BootError> {
            domain.add(reg).map_err(|e| BootError::Domain(r, e))?;
            let k = info.n as usize;
            if k >= START_REGIONS {
                return Err(BootError::Domain(r, DomainError::TooMany));
            }
            let kind = match reg.kind {
                Kind::Anon => REGION_ANON,
                Kind::Phys => REGION_PHYS,
                Kind::Contig => REGION_CONTIG,
            };
            info.regions[k] = RegionRec { base: reg.base, size: reg.size, perm: reg.perm, kind, index, _pad: 0 };
            info.n += 1;
            Ok(())
        };
        add(&mut domain, Region { base: abase, size: alen, perm: R | W, kind: Kind::Anon }, 0)?;
        for c in caps {
            match self.target(r, c)? {
                Target::Mmio(i) => {
                    let m = chip::MMIO[i];
                    add(&mut domain, Region { base: m.base, size: m.size, perm: perm_bits(c.perms) & m.perm, kind: Kind::Phys }, i as u8)?;
                }
                Target::Pipe(i) => {
                    let mut reg = self.pipes[i].region;
                    reg.perm = perm_bits(c.perms) & (R | W);
                    add(&mut domain, reg, i as u8)?;
                }
                Target::Endpoint(_) | Target::Launch(_) => {}
            }
        }

        // Scheduling: the topology's own resolution of class and level.
        let prio = match topo.row_sched(row.name.as_bytes()) {
            RowSched::Apply { priority, .. } => priority,
            _ => return Err(BootError::BadProfile(r)),
        };
        let reserved = row.profile.is_declared();
        let class = classify(prio as u32, reserved, false, IDLE_PRIO, IDLE_PRIO);
        let e = &mut self.ents[s];
        *e = Entity::unborn();
        e.sc.set_class(class, prio as u32);
        if class == Class::Dl {
            let p = row.profile;
            let d = if p.deadline_us == 0 { p.period_us } else { p.deadline_us };
            e.sc.set_times(p.runtime_us as u64, p.period_us as u64, d as u64);
            let q = us_to_ticks(p.runtime_us as u64, TIMEBASE_HZ as u64);
            let t = us_to_ticks(p.period_us as u64, TIMEBASE_HZ as u64);
            let dd = us_to_ticks(d as u64, TIMEBASE_HZ as u64);
            if q == 0 || q > dd || dd > t {
                return Err(BootError::BadProfile(r));
            }
            e.cbs = Cbs::new(q, t, dd, true, 0, 0);
        }

        self.tasks[s] = Task {
            state: State::Unborn,
            frame: Frame::ZERO,
            domain,
            info,
            grants,
            caps_at,
            row: r,
            image,
            wake_at: 0,
            call_gen: 0,
            exit_code: 0,
        };
        Ok(())
    }

    /// The capability table of slot `s`, in its grant.
    fn caps(&mut self, s: usize) -> CapTable<'_> {
        // SAFETY: `caps_at` is the address of `CAPS_PER_TASK` slots carved
        // from the slot's grant at boot, 8-aligned and zeroed; the kernel is
        // the only code that touches a grant, one hart, never re-entered, and
        // the table borrows the kernel, so no two are live at once.
        CapTable::new(unsafe { core::slice::from_raw_parts_mut(self.tasks[s].caps_at as *mut CapSlot, CAPS_PER_TASK) })
    }

    fn queue(&mut self, e: usize) -> &mut EpQueue {
        // SAFETY: `queue_at` is a zeroed `EpQueue` in the server's grant
        // (see `caps`).
        unsafe { &mut *(self.eps[e].queue_at as *mut EpQueue) }
    }

    /// Start slot `s`: clear its memory, mint its capabilities from the row,
    /// and make it runnable at the image's entry.
    fn start(&mut self, s: usize) -> Result<(), BootError> {
        let topo = self.topo();
        let r = self.tasks[s].row;
        let row = &topo.tasks()[r];
        // The task's own part is cleared; its grants are not zeroed but
        // re-initialised, so the capability table keeps its generations: a
        // handle of an earlier incarnation of this slot never resolves again.
        let (abase, alen) = self.tasks[s].grants.app();
        zero(abase, alen);
        for e in 0..self.n_eps {
            if self.eps[e].server == Some(s as u8) {
                *self.queue(e) = EpQueue { head: 0, len: 0, slots: [0; MAX_TASKS] };
                // The capability that serves it is minted again below.
                self.eps[e].revoked = false;
            }
        }
        self.caps(s).clear_all();
        // The console every task is started with (the main kernel's `seed_console`).
        self.caps(s).install(ty::CONSOLE, CapPerms::RW, 0).ok_or(BootError::NoCapSlot(r))?;
        for c in topo.caps_of(row) {
            let (kind, res) = match self.target(r, c)? {
                Target::Endpoint(e) => {
                    if c.perms.contains(CapPerms::READ) && self.eps[e].server != Some(s as u8) {
                        continue; // another slot serves it: one server each
                    }
                    (ty::ENDPOINT, e)
                }
                Target::Mmio(i) => (ty::MMIO, i),
                Target::Pipe(i) => (ty::SHM, i),
                Target::Launch(i) => (ty::LAUNCH, i),
            };
            self.caps(s).install(kind, c.perms, res as u32).ok_or(BootError::NoCapSlot(r))?;
        }
        let t = &mut self.tasks[s];
        // The start block at the top of the task's part, the stack below it.
        let info_at = (abase + alen - core::mem::size_of::<StartInfo>()) & !15;
        // SAFETY: inside the task's own Anon part, which `Grants::split`
        // sized for it and the pool aligned; the task has not run yet.
        unsafe { core::ptr::write(info_at as *mut StartInfo, t.info) };
        t.frame = Frame::ZERO;
        t.frame.pc = self.images[t.image].entry as *const () as usize;
        t.frame.x[GP] = self.info.gp;
        t.frame.x[SP] = info_at;
        t.frame.x[A0] = abase;
        t.frame.x[A0 + 1] = info_at;
        t.state = State::Ready;
        t.call_gen = t.call_gen.wrapping_add(1);
        self.ents[s].wake();
        Ok(())
    }

    // ── the switch ──────────────────────────────────────────────────────

    /// The PMP table of slot `s`: the shared code window, the task's domain,
    /// the rest switched off.
    fn load_domain<H: Hw>(&self, hw: &mut H, s: usize) {
        let mut table = [PmpEntry::OFF; PMP_ENTRIES];
        let code = pmp_core::region(self.info.code.0, self.info.code.1 - self.info.code.0, R | X, GRAIN_LOG2)
            .expect("the code window is aligned to the granularity");
        let mut n = 0;
        for e in code.entries() {
            table[n] = *e;
            n += 1;
        }
        n += self.tasks[s].domain.encode(&mut table[n..]);
        debug_assert!(n <= PMP_ENTRIES);
        hw.program_pmp(&table);
    }

    /// The task to run: the scheduler's pick, with its domain loaded. Called
    /// at the end of every trap; returns the slot, whose frame the glue
    /// restores.
    pub fn schedule<H: Hw>(&mut self, hw: &mut H) -> usize {
        let now = hw.now();
        let next = sched::pick(&mut self.ents[..self.n_tasks], Some(self.cur), now).expect("an idle task is always runnable");
        if next != self.cur || self.ents[next].slice_left == 0 {
            self.seq += 1;
            self.ents[next].dispatched(self.seq, TIMESLICE_TICKS);
        }
        // The domain is reloaded on every return, not only a switch: a task
        // may have been started or killed since, and the table is cheap.
        self.cur = next;
        self.load_domain(hw, next);
        next
    }

    /// The frame of slot `s`.
    pub fn frame(&mut self, s: usize) -> &mut Frame {
        &mut self.tasks[s].frame
    }

    /// The slot running now.
    pub fn current(&self) -> usize {
        self.cur
    }

    /// The state of slot `s`.
    pub fn state(&self, s: usize) -> State {
        self.tasks[s].state
    }

    /// How the task in slot `s` ended (`SYS_EXIT`'s status, or -1 for a fault).
    pub fn exit_code(&self, s: usize) -> isize {
        self.tasks[s].exit_code
    }

    /// The slot of the first task whose row is named `name`.
    pub fn slot_of(&self, name: &str) -> Option<usize> {
        (0..self.n_tasks).find(|&s| self.topo().tasks()[self.tasks[s].row].name.as_str() == name)
    }

    /// Account the time since the last trap to the running task.
    fn account(&mut self, now: u64) {
        let ran = now.saturating_sub(self.last_acct);
        self.last_acct = now;
        let cur = self.cur;
        if self.ents[cur].runnable {
            let e = &mut self.ents[cur];
            if e.cbs.active() && e.sc.class() == Class::Dl && e.cbs.charge(ran) {
                e.cbs.exhaust(now);
            }
        }
    }

    /// A timer tick: wake the sleepers, spend the running task's slice.
    pub fn on_tick<H: Hw>(&mut self, hw: &mut H) {
        let now = hw.now();
        self.account(now);
        for s in 0..self.n_tasks {
            if self.tasks[s].state == State::Sleeping && self.tasks[s].wake_at <= now {
                self.tasks[s].state = State::Ready;
                self.ents[s].wake();
            }
        }
        let cur = self.cur;
        sched::slice_tick(&mut self.ents[cur], self.seq + 1);
        if self.ents[cur].slice_left == 0 {
            self.seq += 1;
        }
    }

    /// A task trapped for something that is not a syscall (a PMP or
    /// alignment fault, an illegal instruction): it ends.
    pub fn fault<H: Hw>(&mut self, hw: &mut H, cause: usize, tval: usize) {
        let now = hw.now();
        self.account(now);
        let s = self.cur;
        let name = self.topo().tasks()[self.tasks[s].row].name.as_str();
        say!(hw, "[MICRO] {}: fault cause={} tval={:#x} pc={:#x}: killed", name, cause, tval, self.tasks[s].frame.pc);
        self.end(hw, s, -1);
    }

    // ── tasks ending ────────────────────────────────────────────────────

    fn complete(&mut self, c: usize, ret: isize) {
        self.tasks[c].frame.x[A0] = ret as usize;
        self.tasks[c].state = State::Ready;
        self.ents[c].wake();
    }

    /// Slot `s` ends with `code`: its capabilities are freed, the callers of
    /// the endpoints it served are told, its own pending call is withdrawn.
    fn end<H: Hw>(&mut self, hw: &mut H, s: usize, code: isize) {
        let prev = self.tasks[s].state;
        self.tasks[s].state = State::Dead;
        self.tasks[s].exit_code = code;
        self.ents[s].runnable = false;
        self.ents[s].ceiling = None;
        self.caps(s).clear_all();
        // Calls waiting on an endpoint this task served.
        for c in 0..self.n_tasks {
            if let State::Calling { ep, .. } = self.tasks[c].state {
                if self.eps[ep as usize].server == Some(s as u8) {
                    self.complete(c, -(Errno::EPEERDIED as isize));
                }
            }
        }
        for e in 0..self.n_eps {
            if self.eps[e].server == Some(s as u8) {
                *self.queue(e) = EpQueue { head: 0, len: 0, slots: [0; MAX_TASKS] };
            }
        }
        // Its own call, still queued or in service.
        if let State::Calling { ep, accepted, .. } = prev {
            if !accepted {
                if let Some(srv) = self.eps[ep as usize].server {
                    if self.tasks[srv as usize].state != State::Dead {
                        self.queue(ep as usize).remove(s);
                    }
                }
            } else if let Some(srv) = self.eps[ep as usize].server {
                self.refresh_boost(srv as usize);
            }
        }
        let name = self.topo().tasks()[self.tasks[s].row].name.as_str();
        say!(hw, "[MICRO] {} (slot {}) ended: {}", name, s, code);
        if s == self.floor {
            say!(hw, "[MICRO] {} is the idle floor: started again", name);
            self.start(s).expect("the floor task started at boot with the same capabilities");
        }
    }

    /// The ceiling slot `srv` serves under: the most urgent of the
    /// endpoints it has an accepted, unanswered call on (none: no boost).
    fn refresh_boost(&mut self, srv: usize) {
        let mut boost: Option<PiAttr> = None;
        for c in 0..self.n_tasks {
            if let State::Calling { ep, accepted: true, .. } = self.tasks[c].state {
                if self.eps[ep as usize].server == Some(srv as u8) {
                    let a = self.eps[ep as usize].ceiling;
                    boost = Some(boost.map_or(a, |b| b.max_urgent(a)));
                }
            }
        }
        self.ents[srv].ceiling = boost;
    }

    // ── syscalls ────────────────────────────────────────────────────────

    /// The running task executed `ecall`: decode, run, and leave the result
    /// in its frame (or leave the frame for the task that completes it).
    pub fn syscall<H: Hw>(&mut self, hw: &mut H) {
        let now = hw.now();
        self.account(now);
        let s = self.cur;
        let f = &mut self.tasks[s].frame;
        f.pc += 4; // past the ecall
        let nr = f.x[A7] as u64;
        let a = [f.x[A0], f.x[A0 + 1], f.x[A0 + 2], f.x[A0 + 3], f.x[A0 + 4], f.x[A0 + 5]];
        let ret: Option<isize> = match nr {
            SYS_EXIT => {
                self.end(hw, s, a[0] as isize);
                None
            }
            SYS_GETPID => Some(s as isize + 1),
            SYS_YIELD => {
                self.ents[s].slice_left = 0;
                self.seq += 1;
                self.ents[s].last_run = self.seq;
                Some(0)
            }
            SYS_SLEEP_UNTIL => {
                // The relative form only: `a0` nanoseconds from now.
                if a[1] as u64 != SLEEP_RELATIVE {
                    Some(-(Errno::EINVAL as isize))
                // The floor never blocks: it is what runs when nothing else can.
                } else if a[0] == 0 || s == self.floor {
                    Some(0)
                } else {
                    self.tasks[s].wake_at = now + (a[0] as u64) * (TIMEBASE_HZ as u64) / 1_000_000_000;
                    self.tasks[s].state = State::Sleeping;
                    self.ents[s].runnable = false;
                    Some(0)
                }
            }
            SYS_INVOKE => Some(self.sys_invoke(hw, s, a, now)),
            SYS_CAP_INFO => Some(self.sys_cap_info(s, a[0], a[1], a[2], a[3])),
            SYS_CAP_CLOSE => Some(self.sys_close_typed(s, a[0])),
            SYS_IPC_FAST_CALL_EP => self.ipc_call(s, a),
            SYS_IPC_FAST_ACCEPT => self.ipc_accept(s),
            SYS_IPC_FAST_REPLY => Some(self.ipc_reply(s, a[0], [a[1], a[2], a[3], a[4]]).map_or_else(|e| e, |()| 0)),
            SYS_IPC_FAST_REPLY_ACCEPT => match self.ipc_reply(s, a[0], [a[2], a[3], a[4], a[5]]) {
                Ok(()) => self.ipc_accept(s),
                // -2 stale, -3 any other refusal: nothing was accepted.
                Err(-2) => Some(-2),
                Err(_) => Some(-3),
            },
            SYS_SPAWN_EX => Some(self.sys_spawn_ex(hw, s, a[0], a[1])),
            _ => Some(-1),
        };
        if let Some(v) = ret {
            self.tasks[s].frame.x[A0] = v as usize;
        }
    }

    /// Whether task `s` may read `[addr, addr + len)`: its domain, or the
    /// code window every task can read (a string literal lives in `.rodata`).
    fn user_can_read(&self, s: usize, addr: usize, len: usize) -> bool {
        let (lo, hi) = self.info.code;
        self.tasks[s].domain.admits(addr, len, R)
            || addr.checked_add(len).is_some_and(|end| addr >= lo && end <= hi)
    }

    /// `SYS_INVOKE` (`azos_abi::invoke`): the register form only, on the
    /// console, whose one op is `WRITE`, and on the task's own domain, whose
    /// one op is the uptime. Any other type of handle has no ops
    /// here, an unknown op is `EINVAL`.
    fn sys_invoke<H: Hw>(&mut self, hw: &mut H, s: usize, a: [usize; 6], now: u64) -> isize {
        let opw = a[1] as u64;
        if opw & !(INVOKE_OP_MASK | INVOKE_FLAGS_KNOWN) != 0 || opw & INVOKE_REGS == 0 {
            return -(Errno::EINVAL as isize);
        }
        if is_domain_self(a[0] as u32) {
            return match op_of(opw) {
                // The 64-bit timebase counter: its low word is the result and
                // what is above it, in `a1` (a word alone wraps in minutes).
                DOMAIN_UPTIME => {
                    let (lo, hi) = uptime_words(now);
                    self.tasks[s].frame.x[A0 + 1] = hi;
                    lo as isize
                }
                _ => -(Errno::EINVAL as isize),
            };
        }
        match self.caps(s).resolve_any(CapHandle::from_raw(a[0] as u32)) {
            Ok((t, _, _)) if t == ty::CONSOLE => match op_of(opw) {
                LOG_CONSOLE_WRITE => {
                    if self.caps(s).resolve(CapHandle::from_raw(a[0] as u32), ty::CONSOLE, CapPerms::WRITE).is_err() {
                        return -(Errno::ECAPPERMS as isize);
                    }
                    self.console_write(hw, s, a[2], a[3])
                }
                _ => -(Errno::EINVAL as isize),
            },
            Ok(_) => -(Errno::ECAPKIND as isize),
            Err(_) => -(Errno::ECAPSTALE as isize),
        }
    }

    fn console_write<H: Hw>(&mut self, hw: &mut H, s: usize, ptr: usize, len: usize) -> isize {
        let len = len.min(256);
        if !self.user_can_read(s, ptr, len) {
            return -1;
        }
        let mut buf = [0u8; 64];
        let mut done = 0;
        while done < len {
            let n = (len - done).min(buf.len());
            hw.read_user(ptr + done, &mut buf[..n]);
            hw.console(&buf[..n]);
            done += n;
        }
        len as isize
    }

    /// `SYS_CAP_INFO`, the lookup query only (`CAP_INFO_LOOKUP`): the other
    /// queries read what this kernel's slots do not keep.
    fn sys_cap_info(&mut self, s: usize, _handle: usize, query: usize, kind: usize, resource: usize) -> isize {
        if query as u64 != CAP_INFO_LOOKUP {
            return -(Errno::EINVAL as isize);
        }
        let Some(kind) = u8::try_from(kind).ok().and_then(CapType::from_raw) else {
            return -(Errno::EINVAL as isize);
        };
        match self.caps(s).lookup(kind, resource as u32) {
            Some(h) => h.as_raw() as isize,
            None => -(Errno::ENOENT as isize),
        }
    }

    fn sys_close_typed(&mut self, s: usize, raw: usize) -> isize {
        match self.caps(s).close(CapHandle::from_raw(raw as u32)) {
            Err(e) => cap_errno(e),
            Ok((ty::ENDPOINT, perms, ep)) if perms.contains(CapPerms::READ) => {
                // The server gave up its endpoint: callers waiting on it are
                // told it is gone, new calls are refused and accept finds
                // nothing, until the row starts again.
                let ep = ep as usize;
                self.eps[ep].revoked = true;
                for c in 0..self.n_tasks {
                    if let State::Calling { ep: e, .. } = self.tasks[c].state {
                        if e as usize == ep {
                            self.complete(c, -(Errno::EREVOKED as isize));
                        }
                    }
                }
                *self.queue(ep) = EpQueue { head: 0, len: 0, slots: [0; MAX_TASKS] };
                self.refresh_boost(s);
                0
            }
            Ok(_) => 0,
        }
    }

    // ── IPC ─────────────────────────────────────────────────────────────

    fn server_alive(&self, e: usize) -> Option<usize> {
        if self.eps[e].revoked {
            return None;
        }
        let srv = self.eps[e].server? as usize;
        match self.tasks[srv].state {
            State::Unborn | State::Dead => None,
            _ => Some(srv),
        }
    }

    /// `SYS_IPC_FAST_CALL_EP`: a0 = endpoint capability (`WRITE`), a1..a4 =
    /// four words, a5 = a capability to move with the request (0: none; it
    /// must carry `TRANSFER`). Blocks until the reply; the result is in a0..a3.
    /// On a 32-bit word the main kernel's SHARE flag (bit 32 of a5) has no
    /// room: a handle fills the register, so only a move exists here.
    fn ipc_call(&mut self, s: usize, a: [usize; 6]) -> Option<isize> {
        let h = CapHandle::from_raw(a[0] as u32);
        let Ok(ep) = self.caps(s).resolve(h, ty::ENDPOINT, CapPerms::WRITE) else { return Some(-1) };
        let ep = ep as usize;
        let Some(srv) = self.server_alive(ep) else { return Some(-1) };
        // A row that holds both ends of an endpoint would queue itself behind
        // a server that is the caller: it blocks forever.
        if srv == s {
            return Some(-1);
        }
        if a[5] != 0 {
            match self.caps(s).resolve_any(CapHandle::from_raw(a[5] as u32)) {
                Ok((_, perms, _)) if perms.contains(CapPerms::TRANSFER) => {}
                _ => return Some(-1),
            }
        }
        self.tasks[s].call_gen = self.tasks[s].call_gen.wrapping_add(1);
        let gen = self.tasks[s].call_gen;
        self.tasks[s].state = State::Calling { ep: ep as u8, gen, accepted: false };
        self.ents[s].runnable = false;
        self.queue(ep).push(s);
        if self.tasks[srv].state == State::Accepting {
            self.deliver(srv);
        }
        None
    }

    /// Hand the oldest queued request of an endpoint `srv` serves to it,
    /// writing its registers: a0 = the exchange handle, a1 = the caller's
    /// TID, a2..a5 = the four words, a6 = the handle of the moved capability
    /// in the server's table (0: none). A request whose capability the
    /// server cannot take (its table is full) fails for the caller with -1
    /// and the next is tried. `false`: nothing was queued.
    fn deliver(&mut self, srv: usize) -> bool {
        loop {
            let mut found = None;
            for e in 0..self.n_eps {
                if self.eps[e].server == Some(srv as u8) {
                    if let Some(c) = self.queue(e).pop() {
                        found = Some((e, c));
                        break;
                    }
                }
            }
            let Some((e, c)) = found else { return false };
            debug_assert!(c != srv, "a call to an endpoint its own caller serves is refused");
            let State::Calling { gen, .. } = self.tasks[c].state else { continue };
            let words = [self.tasks[c].frame.x[A0 + 1], self.tasks[c].frame.x[A0 + 2], self.tasks[c].frame.x[A0 + 3], self.tasks[c].frame.x[A0 + 4]];
            let moved = self.tasks[c].frame.x[A0 + 5];
            let mut moved_handle = 0usize;
            if moved != 0 {
                let closed = self.caps(c).close(CapHandle::from_raw(moved as u32));
                match closed {
                    Ok((kind, perms, res)) => match self.caps(srv).install(kind, perms, res) {
                        Some(h) => moved_handle = h.as_raw() as usize,
                        None => {
                            // Put it back and refuse the call.
                            self.caps(c).install(kind, perms, res);
                            self.complete(c, -1);
                            continue;
                        }
                    },
                    Err(_) => {
                        self.complete(c, -1);
                        continue;
                    }
                }
            }
            self.tasks[c].state = State::Calling { ep: e as u8, gen, accepted: true };
            let f = &mut self.tasks[srv].frame;
            f.x[A0] = ((gen as usize) << 8) | c;
            f.x[A0 + 1] = c + 1;
            f.x[A0 + 2] = words[0];
            f.x[A0 + 3] = words[1];
            f.x[A0 + 4] = words[2];
            f.x[A0 + 5] = words[3];
            f.x[A0 + 6] = moved_handle;
            self.tasks[srv].state = State::Ready;
            self.ents[srv].wake();
            self.refresh_boost(srv);
            return true;
        }
    }

    /// `SYS_IPC_FAST_ACCEPT`: the next request, or wait for one.
    fn ipc_accept(&mut self, s: usize) -> Option<isize> {
        if !self.deliver(s) {
            // A task that serves no live endpoint (it holds no `READ`, or it
            // closed it) would wait for a request nobody can send.
            let serves = (0..self.n_eps).any(|e| self.eps[e].server == Some(s as u8) && !self.eps[e].revoked);
            if !serves {
                return Some(-1);
            }
            self.tasks[s].state = State::Accepting;
            self.ents[s].runnable = false;
        }
        None
    }

    /// `SYS_IPC_FAST_REPLY`: answer the exchange `handle` names with four
    /// words. `Err(-2)`: the exchange is gone (stale handle); `Err(-1)`: any
    /// other refusal (not yours, not accepted).
    fn ipc_reply(&mut self, s: usize, handle: usize, words: [usize; 4]) -> Result<(), isize> {
        let c = handle & 0xff;
        let gen = (handle >> 8) as u16;
        if c >= self.n_tasks {
            return Err(-1);
        }
        let State::Calling { ep, gen: g, accepted } = self.tasks[c].state else { return Err(-2) };
        if g != gen {
            return Err(-2);
        }
        if !accepted || self.eps[ep as usize].server != Some(s as u8) {
            return Err(-1);
        }
        let f = &mut self.tasks[c].frame;
        f.x[A0..A0 + 4].copy_from_slice(&words);
        self.tasks[c].state = State::Ready;
        self.ents[c].wake();
        self.refresh_boost(s);
        Ok(())
    }

    // ── spawn ───────────────────────────────────────────────────────────

    /// `SYS_SPAWN_EX` with no `SpawnReq` (a1 = 0): a0 = the image's name (a
    /// NUL-terminated string, at most 12 bytes). The caller must hold a
    /// launch capability with `EXEC` on the row; the first slot of the row
    /// that is not running starts with the row's capabilities. Returns its
    /// TID. -EACCES: no row, no capability, nothing free to start.
    fn sys_spawn_ex<H: Hw>(&mut self, hw: &mut H, s: usize, path: usize, req: usize) -> isize {
        if req != 0 {
            return -(Errno::EINVAL as isize);
        }
        let mut name = [0u8; 12];
        let mut n = 0;
        while n < name.len() {
            if !self.user_can_read(s, path.wrapping_add(n), 1) {
                return -(Errno::EFAULT as isize);
            }
            let mut b = [0u8; 1];
            hw.read_user(path + n, &mut b);
            if b[0] == 0 {
                break;
            }
            name[n] = b[0];
            n += 1;
        }
        if n == 0 || n == name.len() {
            return -(Errno::EINVAL as isize);
        }
        let name = &name[..n];
        let topo = self.topo();
        let Some(row) = topo.tasks().iter().position(|t| t.name.as_bytes() == name) else {
            return -(Errno::EACCES as isize);
        };
        let Some(h) = self.caps(s).lookup(ty::LAUNCH, row as u32) else {
            return -(Errno::EACCES as isize);
        };
        if let Err(e) = self.caps(s).resolve(h, ty::LAUNCH, CapPerms::EXEC) {
            return cap_errno(e);
        }
        let Some(slot) = (0..self.n_tasks).find(|&k| {
            self.tasks[k].row == row && matches!(self.tasks[k].state, State::Unborn | State::Dead)
        }) else {
            return -(Errno::EAGAIN as isize);
        };
        if self.start(slot).is_err() {
            return -1;
        }
        slot as isize + 1
    }
}

/// `mtime` as the two words `DOMAIN_UPTIME` returns it in: the low machine word
/// in a0 and what is above it in a1 (always 0 on a 64-bit word). A 32-bit
/// word alone wraps in minutes at the timebase (214 s to read as negative at
/// 10 MHz, 7 min to wrap), so the counter is not returned truncated: a
/// reader joins the pair ([`join_words`]); one that wants only a short
/// interval subtracts the a0 words, which is right across the wrap.
pub fn uptime_words(now: u64) -> (usize, usize) {
    let (lo, hi) = split_words(now, usize::BITS);
    (lo as usize, hi as usize)
}

/// [`uptime_words`] for a word of `bits` bits.
pub const fn split_words(now: u64, bits: u32) -> (u64, u64) {
    if bits >= 64 {
        (now, 0)
    } else {
        (now & ((1 << bits) - 1), now >> bits)
    }
}

/// The counter back from the two words of a `bits`-bit machine.
pub const fn join_words(lo: u64, hi: u64, bits: u32) -> u64 {
    if bits >= 64 {
        lo
    } else {
        (hi << bits) | lo
    }
}

/// `CapPerms` as PMP rights.
fn perm_bits(p: CapPerms) -> u8 {
    (if p.contains(CapPerms::READ) { R } else { 0 })
        | (if p.contains(CapPerms::WRITE) { W } else { 0 })
        | (if p.contains(CapPerms::EXEC) { X } else { 0 })
}

/// The errno a capability refusal answers with, as in the main kernel.
fn cap_errno(e: CapError) -> isize {
    -(match e {
        CapError::Stale => Errno::ECAPSTALE,
        CapError::WrongKind => Errno::ECAPKIND,
        CapError::MissingPerms => Errno::ECAPPERMS,
    } as isize)
}

// A handle's kind field must stay below the sign bit of a 32-bit result.
const _: () = assert!(
    (ty::ENDPOINT.raw() as u32) < 32 && (ty::MMIO.raw() as u32) < 32 && (ty::SHM.raw() as u32) < 32 && (ty::LAUNCH.raw() as u32) < 32,
    "a handle would read as a negative syscall result on rv32"
);
