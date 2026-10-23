// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's half of the crash dump (Kconfig `CRASHDUMP`): what a fault
//! that kills a ring-3 task leaves behind. The layout, the file ring and the
//! report are `azos_recovery::crashdump`; this file gathers the task's state
//! at the moment of the fault and moves it to its two places.
//!
//! **On the fault path** ([`capture`], called from `Kernel::crashdump` before
//! the kill tears the task down): the registers of the trap, a window of the
//! stack read from the page table without committing or copying a page, the
//! maps (`azos_mm::vmm::user_runs`), the last decision records and the
//! SHA-256 of the task's image go into a slot of the crash ring. No I/O, no
//! allocation and no lock but the two capability and tree tables, so a fault
//! costs a fixed amount and a faulting RT task never waits on a device. First
//! of all, a 32-byte record (task, status) goes on the flight recorder's ring
//! (`logger::log_error`, queue only), which the log flusher writes out and a
//! reset does not lose: the Log half of the owner's "Log + file". It is the
//! whole of the Log half: the dump itself is only ever read as a file.
//!
//! **Off it** ([`drain`], a job of the log flusher task): the dump is written
//! as `CRASHn.DMP` in the root of the first write tree the faulting Domain holds
//! (a `Cap<Dir>`) through `azos_fs::crash_log::write_beneath`. The tree is
//! resolved at the fault, to its root PATH, which the slot carries: the task's
//! capability table is gone by the time the flusher runs, and a drain that
//! waits (a full job table, a slow device) never depends on a table that moved
//! meanwhile. A Domain whose row holds no write tree has nowhere to put a dump:
//! it takes no slot and is not encoded (the record on the flight recorder is
//! all it leaves); `why crash` reads files, so a slot with no file would be
//! RAM nothing reads.
//!
//! The ring is a state machine per slot, not a lock: the fault path may run
//! on several harts at once and the flusher holds a slot across a device wait
//! (`FREE -> FILLING -> PENDING -> WRITING -> DONE`). A slot being filled or
//! written is never touched; when every slot is busy or waiting for its file,
//! the oldest waiting one is overwritten and the drop is counted.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use azos_abi::cap::{ty, CapPerms};
use azos_ipc::file_cap::{self, TREE_PATH_MAX};
use azos_recovery::crashdump as cd;

use super::kernel::ArchFrame;

const STACK: usize = azos_limits::CRASHDUMP_STACK_BYTES as usize;
const MAPS: usize = azos_limits::CRASHDUMP_MAPS as usize;
const DECISIONS: usize = azos_limits::CRASHDUMP_DECISIONS as usize;
const RING: usize = azos_limits::CRASHDUMP_RING as usize;
const FILES: usize = azos_limits::CRASHDUMP_FILES as usize;
/// A ring slot: the largest dump these bounds make.
const SLOT_BYTES: usize = cd::max_bytes(STACK, MAPS, DECISIONS);

const _: () = assert!(STACK <= cd::MAX_STACK && MAPS <= cd::MAX_MAPS && DECISIONS <= cd::MAX_DECISIONS);
const _: () = assert!(FILES >= 1 && FILES <= cd::MAX_SLOTS && RING >= 1);

/// What [`capture`] puts on the faulting task's kernel stack: the register
/// snapshot (`with_user_regs`, FP state included: an XSAVE area on x86_64),
/// the stack window, the map runs and their dump form, the decisions, the
/// tree path. A user fault enters at the top of that stack, so the capture
/// may take half of what is usable (the size less its guard page); the rest
/// is for the trap frame and the paths below (K1 L6: with the stack bounds
/// at their limits the capture alone could overflow it). A configuration
/// that breaks it is refused here, not on the first fault.
const CAPTURE_STACK_BYTES: usize = core::mem::size_of::<azos_sched::UserRegs>()
    + cd::MAX_REGS * 8
    + STACK
    + MAPS * (core::mem::size_of::<azos_mm::vmm::UserRun>() + core::mem::size_of::<cd::Map>())
    + DECISIONS * core::mem::size_of::<cd::Decision>()
    + TREE_PATH_MAX;
const _: () = assert!(
    CAPTURE_STACK_BYTES <= (azos_limits::KERNEL_STACK_SIZE_BYTES - (1 << azos_limits::PAGE_SHIFT)) / 2,
    "crash dump capture takes over half the kernel stack: lower CRASHDUMP_STACK_BYTES / CRASHDUMP_MAPS / \
     CRASHDUMP_DECISIONS (or X86_XSAVE_AREA_BYTES), or raise KERNEL_STACK_SIZE_KB"
);

/// The `subsystem` byte of the flight-recorder record a fault leaves
/// (`logger::log_error`): `C`.
const LOG_SUBSYSTEM: u8 = b'C';

const FREE: u8 = 0;
const FILLING: u8 = 1;
/// Filled, its file not written yet.
const PENDING: u8 = 2;
const WRITING: u8 = 3;
const DONE: u8 = 4;

struct Slot {
    state: AtomicU8,
    /// When the slot was claimed (the order of the ring).
    stamp: AtomicU32,
    /// Bytes of the dump; valid from `PENDING` on.
    len: AtomicU32,
    /// Bytes of `root`; valid from `PENDING` on.
    root_len: AtomicU32,
    tid: AtomicU32,
    /// The root path of the Domain's write tree, resolved at the fault.
    root: UnsafeCell<[u8; TREE_PATH_MAX]>,
    bytes: UnsafeCell<[u8; SLOT_BYTES]>,
}

// SAFETY: `bytes` and `root` are touched only by the owner of the slot's state: the
// filler between `FILLING` and `PENDING`, the flusher between `WRITING` and
// `DONE`; every handover is a release store read by an acquire compare-exchange.
unsafe impl Sync for Slot {}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY: Slot = Slot {
    state: AtomicU8::new(FREE),
    stamp: AtomicU32::new(0),
    len: AtomicU32::new(0),
    root_len: AtomicU32::new(0),
    tid: AtomicU32::new(0),
    root: UnsafeCell::new([0; TREE_PATH_MAX]),
    bytes: UnsafeCell::new([0; SLOT_BYTES]),
};
static SLOTS: [Slot; RING] = [EMPTY; RING];
static CLOCK: AtomicU32 = AtomicU32::new(0);
/// Dumps overwritten before their file was written, and dumps that did not fit
/// (reported by each file write, the one place it is read).
static DROPPED: AtomicU32 = AtomicU32::new(0);

/// Take a slot to fill: a free or written one (the oldest), else the oldest
/// waiting one (its dump is lost, counted). `None` when every slot is busy.
fn claim() -> Option<&'static Slot> {
    for lost in [false, true] {
        for _ in 0..RING {
            let want = |s: u8| if lost { s == PENDING } else { s == FREE || s == DONE };
            let mut best: Option<(&'static Slot, u8, u32)> = None;
            for s in SLOTS.iter() {
                let st = s.state.load(Ordering::Acquire);
                let stamp = s.stamp.load(Ordering::Relaxed);
                if want(st) && best.is_none_or(|(_, _, b)| b.wrapping_sub(stamp) as i32 > 0) {
                    best = Some((s, st, stamp));
                }
            }
            let Some((s, st, _)) = best else { break };
            if s.state.compare_exchange(st, FILLING, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                if lost {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                }
                s.stamp.store(CLOCK.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
                return Some(s);
            }
        }
    }
    DROPPED.fetch_add(1, Ordering::Relaxed);
    None
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("crash: no register dump order for this ISA: a new ISA names its `registers` here");

/// The trap's registers in the dump's order, and the ISA that order is.
#[inline(never)]
fn registers<F: ArchFrame>(frame: &F, out: &mut [u64; cd::MAX_REGS]) -> (cd::Isa, usize) {
    frame.with_user_regs(true, |r| {
        #[cfg(target_arch = "riscv64")]
        {
            // `regs[0]` is the frame tag, not `x0`: the dump's `zero` stays zero.
            for i in 1..32 {
                out[i] = r[i] as u64;
            }
            (cd::Isa::Riscv64, 32)
        }
        #[cfg(target_arch = "aarch64")]
        {
            out[..31].copy_from_slice(&r.gpr);
            out[31] = r.sp_el0;
            out[32] = r.spsr_el1;
            out[33] = r.tpidr_el0;
            (cd::Isa::Aarch64, 34)
        }
        #[cfg(target_arch = "x86_64")]
        {
            out[..15].copy_from_slice(&r.gpr);
            out[15] = r.rsp;
            out[16] = r.rflags;
            out[17] = r.fs_base;
            out[18] = r.gs_base;
            (cd::Isa::X86_64, 19)
        }
    })
}

/// Copy the task's stack from `sp` up into `out`, as far as the page table
/// maps it readable: nothing is committed, copied-on-write or allocated (the
/// read `prof.rs` does from the timer interrupt). How many bytes.
fn read_stack(pt: usize, sp: u64, out: &mut [u8]) -> usize {
    // Each page in one access section (uaccess-pin).
    azos_mm::uaccess::copy_in_resident(pt, out.as_mut_ptr(), sp as usize, out.len())
}

/// The SHA-256 of the image the build copied under `name`: the key of its
/// symbol file. All zero for a task the tables do not hold (a Linux guest
/// program, an image from elsewhere).
fn image_digest(name: &str) -> [u8; 32] {
    azos_sched::seccomp::digest_named(name.as_bytes()).unwrap_or([0; 32])
}

/// The root path of the first write tree (`Cap<Dir>`) task `tid`'s Domain
/// holds, written to `out`: its length, `None` when it holds none. Live slots
/// only, by the authority a use resolves with. The path, not the tree's
/// resource, is what the dump keeps: it names the same directory whatever
/// happens to the capability afterwards.
fn write_tree(tid: u32, out: &mut [u8; TREE_PATH_MAX]) -> Option<usize> {
    let mut found = 0u32;
    let _ = azos_ipc::cap_store::with_table(tid, |t| {
        t.lookup_where(ty::FILE, |r, _badge, perms| {
            let hit = file_cap::is_tree_resource(r) && perms.contains(CapPerms::WRITE);
            if hit {
                found = r;
            }
            hit
        })
    });
    // Outside the capability table's lock: the tree table is a lock of its own.
    file_cap::tree_path(found, out)
}

/// The latest decisions about the dying task, oldest first, into `out`; how
/// many. Only a record whose subject is a TID (`RuleInfo::subject` "tid")
/// naming this thread or its process: the dump is written into the task's own
/// tree, and the kernel-wide last N it used to carry disclosed other Domains'
/// refusals (subject, rule, verdict) to it (K1 L5). Scans back through every
/// record still held, as `azos_decision::query` does, not only the last N.
fn own_decisions(tid: u32, out: &mut [cd::Decision; DECISIONS]) -> usize {
    use azos_decision as d;
    let span = (if d::ON { d::ENTRIES } else { 0 }).max(if d::DURABLE { d::JOURNAL_ENTRIES } else { 0 }) as u64;
    let proc = azos_sched::current_proc_tid();
    let last = d::total();
    let mut n = 0;
    let mut id = last;
    while n < DECISIONS && id > 0 && last - id < span {
        if let Some(p) = d::lookup(id) {
            let by_tid = d::RULES.get(p.rule as usize).is_some_and(|r| r.subject == "tid");
            if by_tid && (p.subject == tid || p.subject == proc) {
                out[n] = cd::Decision { seq: id, rule: p.rule, verdict: p.verdict, subject: p.subject, n: p.n, ts: p.clock_ns };
                n += 1;
            }
        }
        id -= 1;
    }
    out[..n].reverse();
    n
}

/// Leave the dump of the running task, which a fault is about to kill with
/// `status`. Called on the fault path, before the kill.
pub(super) fn capture<F: ArchFrame>(frame: &F, status: i32) {
    let pt = azos_sched::current_user_pt();
    if pt == 0 {
        return;
    }
    let tid = azos_sched::current_task_tid();
    // The record on the flight recorder's ring (queue only, no I/O): task and
    // status, kept across a reset, whether or not there is room in the crash
    // ring or a directory to write the dump to.
    azos_actuation::logger::log_error(LOG_SUBSYSTEM, status as u16, tid);
    // No write tree, no file, so no dump: nothing reads a dump that is not one.
    let mut root = [0u8; TREE_PATH_MAX];
    let Some(root_len) = write_tree(tid, &mut root) else { return };
    let Some(slot) = claim() else { return };
    let name = azos_sched::current_task_name();
    let (pc, sp) = (frame.pc(), frame.user_sp());

    let mut regs = [0u64; cd::MAX_REGS];
    let (isa, nregs) = registers(frame, &mut regs);

    let mut runs = [azos_mm::vmm::UserRun::default(); MAPS];
    let (stored, total) = azos_mm::vmm::user_runs(pt, &mut runs);
    let mut maps = [cd::Map::default(); MAPS];
    for (m, r) in maps.iter_mut().zip(&runs[..stored]) {
        let flag = |on: bool, bit: u32| if on { bit } else { 0 };
        *m = cd::Map {
            start: r.start as u64,
            end: r.end as u64,
            flags: flag(r.read, cd::MAP_R) | flag(r.write, cd::MAP_W) | flag(r.exec, cd::MAP_X),
        };
    }

    let mut decisions = [cd::Decision::default(); DECISIONS];
    let nd = own_decisions(tid, &mut decisions);

    let mut stack = [0u8; STACK];
    let nstack = read_stack(pt, sp, &mut stack);

    let dump = cd::Dump {
        isa,
        tid,
        status,
        cause: frame.fault_cause(),
        cpu: azos_sched::smp::current_cpu_id() as u32,
        ticks: azos_drv_sys::timebase::now(),
        pc,
        sp,
        fault_addr: frame.fault_addr(),
        image: image_digest(name),
        name: name.as_bytes(),
        regs: &regs[..nregs],
        maps: &maps[..stored],
        maps_total: total.min(u16::MAX as usize) as u16,
        decisions: &decisions[..nd],
        stack_base: sp,
        stack: &stack[..nstack],
    };
    // SAFETY: the slot is `FILLING`, ours alone.
    let bytes = unsafe { &mut *slot.bytes.get() };
    let Ok(len) = cd::encode(&dump, bytes) else {
        // The bounds make this unreachable; a slot is never left half filled.
        DROPPED.fetch_add(1, Ordering::Relaxed);
        slot.state.store(FREE, Ordering::Release);
        return;
    };
    // SAFETY: the slot is `FILLING`, ours alone.
    unsafe { (&mut *slot.root.get())[..root_len].copy_from_slice(&root[..root_len]) };
    slot.len.store(len as u32, Ordering::Relaxed);
    slot.tid.store(tid, Ordering::Relaxed);
    slot.root_len.store(root_len as u32, Ordering::Relaxed);
    slot.state.store(PENDING, Ordering::Release);
    // The file is the log flusher's to write. A full job table leaves the dump
    // pending: the next fault's request (or the next pass that has room) writes it.
    let _ = azos_actuation::logger::logger_defer_io(drain);
}

/// The log flusher's job: write every dump that waits for its file.
fn drain() {
    for slot in SLOTS.iter() {
        if slot.state.compare_exchange(PENDING, WRITING, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            write_file(slot);
            slot.state.store(DONE, Ordering::Release);
        }
    }
}

/// Write one dump to the next slot of the file ring beneath its directory.
fn write_file(slot: &Slot) {
    use azos_fs::crash_log::read_head_beneath;
    let tid = slot.tid.load(Ordering::Relaxed);
    // SAFETY: the slot is `WRITING`, the flusher's alone.
    let root = unsafe { &(&*slot.root.get())[..slot.root_len.load(Ordering::Relaxed) as usize] };
    let mut table = azos_fs::ScratchFds::new();
    let mut serials = [None; FILES];
    for (i, serial) in serials.iter_mut().enumerate() {
        let mut rel = [0u8; cd::REL_MAX];
        let k = cd::slot_rel(i, &mut rel);
        let mut head = [0u8; 24];
        *serial = read_head_beneath(&mut table, root, &rel[..k], &mut head)
            .and_then(|got| cd::peek(&head[..got]))
            .map(|p| p.serial);
    }
    let (file, serial) = cd::next_slot(&serials);
    let mut rel = [0u8; cd::REL_MAX];
    let k = cd::slot_rel(file, &mut rel);
    // SAFETY: the slot is `WRITING`, the flusher's alone.
    let bytes = unsafe { &mut (&mut *slot.bytes.get())[..slot.len.load(Ordering::Relaxed) as usize] };
    cd::set_serial(bytes, serial);
    let wrote = azos_fs::crash_log::write_beneath(&mut table, root, &rel[..k], bytes);
    azos_drv_sys::kwarn!("[CRASHDUMP] tid {}: {:?} as {}/{} (dump {}, {} lost so far)",
        tid, wrote, core::str::from_utf8(root).unwrap_or("?"), core::str::from_utf8(&rel[..k]).unwrap_or("?"), serial,
        DROPPED.load(Ordering::Relaxed));
}
